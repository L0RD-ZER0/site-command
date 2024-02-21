<?php

namespace EE\Site\Type;
use GuzzleHttp\Client;
use League\Flysystem\Adapter\Local;
use League\Flysystem\Adapter\NullAdapter;
use League\Flysystem\Filesystem;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Output\ConsoleOutput;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Normalizer\GetSetMethodNormalizer;
use Symfony\Component\Serializer\Serializer;
use function EE\Site\Utils\reload_global_nginx_proxy;
use function EE\Utils\get_config_value;

class ChallengeType {
	const DNS_MANUAL = 'dns-manual';
	const DNS_CF = 'dns-cf';
	const HTTP = 'http';
}

class Site_SSL {
	private $acme_sh_init;
	private $acme_sh = 'docker exec -i service_global-acme-sh-daemon sh -c ';
	// Volume needs three files:
	// - <domain>.chain.pem
	// - <domain>.key
	// - <domain>.crt
	//
	// Acme.sh gives the following files:
	// - <domain>.cer  (copied to <domain>.crt)
	// - <domain>.key  (copied to <domain.key>)
	// - ca.cer
	// - fullchain.cer  (copied to <domain.chain.pem>)

	/**
	 * @var string Certificate authority api to make use of
	 *
	 * @since 3.3.0
	 */
	private $certificate_authority = 'letsencrypt';
	private $challenges;
	private $conf_dir;

	function __construct() {
		$this->conf_dir = EE_ROOT_DIR . '/services/nginx-proxy/acme-sh-conf';
		$webroot = EE_ROOT_DIR . '/services/nginx-proxy/html/';
		$this->acme_sh_init = 'docker run --rm --name service_global-acme-sh-daemon'
								. " -v \"$this->conf_dir:/acme.sh\""
								. " -v \"$webroot:/webroot\""
								. ' -v "global-nginx-proxy_certs:/certs-vol" -d neilpang/acme.sh daemon';
		$this->challenges = [
			ChallengeType::DNS_MANUAL   => new Site_SSL\DNS_Manual( $this ),
			ChallengeType::DNS_CF       => new Site_SSL\DNS_CF( $this ),
			ChallengeType::HTTP         => new Site_SSL\HTTP( $this ),
		];
	}


	/**
	 * Function to execute an acme.sh command in its docker container
	 *
	 * @param string $command Command to be executed.
	 * @param array $obfuscate Array of strings to obfuscate in logs.
	 * @param bool $echo_stdout Whether to echo stdout or not.
	 * @param bool $echo_stderr Whether to echo stderr or not.
	 * @param bool $exit_on_error Whether to exit on error or not.
	 *
	 * @return bool ``true`` on success, ``false`` on failure.
	 *
	 * @since 3.3.0
	 *
	 */
	public function exec( string $command, array $obfuscate = [], bool $echo_stdout = false, bool $echo_stderr = false, bool $exit_on_error = false ) : bool {
		$command = str_replace( "'", "'\''", $command );
		$command = $this->acme_sh . "'" . $command . "'";
		\EE::debug( 'Executing: ' . $command );
		return \EE::exec( $command, $echo_stdout, $echo_stderr, $obfuscate, $exit_on_error );
	}

	/**
	 * Starts acme.sh service container in daemon mode
	 *
	 * @return bool ``true`` on success, ``false`` on failure
	 *
	 * @since 3.3.0
	 */
	public function init() : bool {
		$exists = \EE::exec(
			'
			docker ps | grep service_global-acme-sh-daemon
			'
		);
		return ( $exists || \EE::exec( $this->acme_sh_init ) ) &&
				$this->exec(
					'mkdir -p /acme.sh;'
					// . 'echo export LE_WORKING_DIR=/acme.sh >>  /etc/profile;'
					 . 'acme.sh --set-default-ca --server ' . $this->certificate_authority . ';'
					// . 'echo export DEFAULT_ACME_SERVER=$DEFAULT_ACME_SERVER >>  /etc/profile;'
				);
	}

	/**
	 * Loads certificates from volume
	 *
	 * Loads certificates in volume to certificate home so acme.sh can make use of them.
	 * Assumes that <domain>.crt, <domain>.key, <domain>.chain.pem, and <domain>.conf
	 * are present in the volume. Otherwise, acme.sh will not be able to use them.
	 *
	 * @param string $domain Domain for which certificates are to be loaded.
	 *
	 * @return bool ``true`` on success, ``false`` on failure.
	 *
	 * @since 3.3.0
	 */
	public function load_certificates( string $domain ) : bool {
		return $this->exec(
			"
			mkdir -p /acme.sh/$domain;
			cp /certs-vol/$domain.* /acme.sh/$domain;
		"
		);
	}

	/**
	 * Unloads certificates to volume
	 *
	 * This function updates the certificates in the volume to match those in
	 ** certificate home and after converting them to required format.
	 *
	 * @param string $domain Domain for which certificates are to be unloaded.
	 *
	 * @return bool ``true`` on success, ``false`` on failure.
	 *
	 * @since 3.3.0
	 */
	public function unload_certificates( string $domain ) : bool {
		return $this->convert_certificates( $domain ) &&
			$this->exec(
				"mv /acme.sh/$domain/$domain.crt /certs-vol/$domain.crt;"
				. "mv /acme.sh/$domain/$domain.cer /certs-vol/$domain.cer;"
				. "mv /acme.sh/$domain/$domain.chain.pem /certs-vol/$domain.chain.pem;"
				. "mv /acme.sh/$domain/$domain.key /certs-vol/$domain.key;"
				. "mv /acme.sh/$domain/$domain.conf /certs-vol/$domain.conf;"
			);
	}

	/**
	 * Converts the output certificates from acme.sh to our required format
	 *
	 * @param string $domain domain for certificate
	 *
	 * @return bool ``true`` on success, ``false`` on failure
	 *
	 * @since 3.3.0
	 */
	private function convert_certificates( string $domain ) : bool {
		return $this->exec(
			'for cert_dir in /acme.sh/*_ecc; do
					domain=$(basename $cert_dir | sed -e s/_ecc//);
					rm -rf /acme.sh/$domain;
					mv -f $cert_dir /acme.sh/$domain;
			done;'  // Move ECC certificates to non-ECC directory, if present
			. "cp /acme.sh/$domain/fullchain.cer /acme.sh/$domain/$domain.chain.pem;"
			. "cp /acme.sh/$domain/fullchain.cer /acme.sh/$domain/$domain.crt;"
		);
	}

	/**
	 * Checks if a certificate is already present for a domain
	 *
	 * @param string $domain Domain for which certificate is to be checked.
	 *
	 * @return bool ``true`` if certificate is already present, ``false`` otherwise.
	 *
	 * @since 3.3.0
	 */
	private function has_certificate( string $domain ) : bool {
		return $this->exec( "test -f /certs-vol/$domain.conf" );
	}

	/**
	 * Function to register mail to letsencrypt.
	 *
	 * @param string $email Mail id to be registered.
	 *
	 * @return bool ``true`` on success, ``false`` on failure
	 *
	 * @since 3.3.0
	 */
	public function register( string $email ) : bool {
		return $this->exec(
			'acme.sh --register-account --email ' . $email
		);
	}

	/**
	 * @param array $domains Domains for which certificate is to be revoked.
	 * @param int $reason Reason for revoking certificate
	 * @param bool $remove Whether to remove certificate from volume or not
	 *
	 * @return bool ``true`` on success, ``false`` on failure
	 *
	 * @since 3.3.0
	 */
	public function revoke_certificates( array $domains, int $reason = 0, bool $remove = true ) : bool {
		foreach ( $domains as $domain ) {
			$res = $this->load_certificates( $domain );
			if ( ! $res ) {
				\EE::debug( "Couldn't load certificate for $domain" );
				return false;
			}
			$res = $this->exec( "acme.sh --revoke -d $domain --revoke-reason $reason" );
			if ( ! $res ) {
				\EE::debug( "Couldn't revoke certificate for $domain" );
				return false;
			}
			if ( $remove ) {
				if ( ! $this->remove_certificate( $domain ) ) {
					\EE::debug( "Couldn't remove certificate for $domain" );
					return false;
				}
				\EE::debug( "Successfully removed certificate for $domain" );
				return true;
			}
			$res = $this->unload_certificates( $domain );
			if ( ! $res ) {
				\EE::debug( "Couldn't unload certificate for $domain" );
				return false;
			}
			\EE::debug( "Successfully revoked certificate for $domain" );
		}
		return true;
	}

	/**
	 * Check expiry if a certificate is already expired.
	 *
	 * @param string $domain Domain for which certificate is to be checked.
	 *
	 * @return bool ``true`` if certificate is already expired, ``false`` otherwise.
	 *
	 * @since 3.3.0
	 */
	public function is_already_expired( string $domain ) : bool {
		return $this->exec(
			"timestamp=\"$( cat /certs-vol/$domain.conf | grep Le_CertCreateTime= | sed -e s/Le_CertCreateTime=// -e \"s/'//g\" )\""
				. ' timestamp=$(date -d "$(date -d @$timestamp)+90days" +%s);'  // Add 90 days to creation time
				. ' echo -e "Timestamp for Expiration Date: $timestamp\\nCurrent Timestamp: $(date +%s)";'
				. ' if [ $timestamp -lt $(date +%s) ]; then'  // Timestamp less than now, i.e. date has gone by
					. ' echo Certificate has Expired;'
					. ' exit 0;'  // true
				. ' else'
					. ' echo Certificate has Not Expired;'
				. ' exit 1;'  // false
				. ' fi'
			, [], true
		);
	}

	/**
	 * Check expiry of a certificate.
	 *
	 * @param string $domain Domain for which certificate is to be checked.
	 *
	 * @returns bool ``true`` if certificate should be renewed, ``false`` otherwise.
	 *
	 * @since 3.3.0
	 */
	public function is_renewal_necessary( string $domain ) : bool {
		// Check if certificate expires in next 30 days or so
		return $this->exec(
			"timestamp=\"$( cat /certs-vol/$domain.conf | grep Le_NextRenewTime= | sed -e s/Le_NextRenewTime=// -e \"s/'//g\" )\""
			. ' timestamp=$(date -d @$timestamp +%s);'
			. ' echo -e "Timestamp for Renewal Date: $timestamp\\nCurrent Timestamp: $(date +%s)";'
			. ' if [ $timestamp -lt $(date +%s) ]; then'  // Timestamp less than now, i.e. date has gone by
				. ' echo Renewal is Necessary;'
				. ' exit 0;'  // true
			. ' else'
				. ' echo Renewal is not necessary;'
				. ' exit 1;'  // false
			. ' fi' , [], true
		);
	}

	/**
	 * Determines the type of challenge to make use of for issuing a certificate
	 *
	 * @param string $domain Domain for which certificate is to be issued.
	 * @param string $preferred_challenge Challenge type to be preferred.
	 *
	 * @return string Challenge type to be used.
	 */
	private function get_challenge_type( string $domain, string $preferred_challenge = '' ) : string {
		if ( ! ( '*.' === substr( $domain, 0, 2 ) ) &&
			 ChallengeType::HTTP === $preferred_challenge ) {
			return ChallengeType::HTTP;
		}

		// Check if cloudflare api key is present or not
		$cloudflare_api_key = get_config_value( 'cloudflare_api_key' );
		if ( ! empty( $cloudflare_api_key ) ) {
			return ChallengeType::DNS_CF;
		}

		return ChallengeType::DNS_MANUAL;
	}

	/**
	 * Issue a certificate for a domain
	 *
	 * @param string $domain Domain for which certificate is to be issued.
	 * @param string[] $alt_names Domains for which certificate is to be issued.
	 * @param string $email Mail id to be registered.
	 * @param bool $force Whether to force issue certificate or not.
	 *
	 * @return bool ``true`` on success, ``false`` on failure.
	 *
	 * @since 3.3.0
	 */
	public function issue_certificate( string $domain, array $alt_names, string $email, bool $force = false ) : bool {
		if ( $this->has_certificate( $domain ) && ! $force ) {
			if ( ! $this->is_renewal_necessary( $domain ) ) {
				return true;
			}

			return $this->renew_certificate( $domain );
		}

		// determine challenge type
		$challenge_type = $this->get_challenge_type( $domain );
		\EE::debug( "Selected Challenge Type: $challenge_type" );

		// return $this->challenges[ $challenge_type ]->solve( $domain, $alt_names, $email, $force );
		$solver = $this->challenges[ $challenge_type ];
		return $solver->solve( $domain, $alt_names, $email, $force );
	}

	/**
	 * Renews a certificate for a domain
	 *
	 * @param string $domain Domain for which certificate is to be renewed.
	 * @param bool $force Whether to force the renewal for a domain or not.
	 *
	 * @return bool ``true`` on success, ``false`` on failure.
	 *
	 * @since 3.3.0
	 */
	public function renew_certificate( string $domain, bool $force = false ) : bool {
		if ( ! $force && ! $this->is_renewal_necessary( $domain ) ) {
			return true;
		}

		// Apparently, acme.sh renews http based challenges over http, which requires proxy to allow acme challenges to pass
		$fs = new \Symfony\Component\Filesystem\Filesystem();
		$fs->copy( SITE_TEMPLATE_ROOT . '/vhost.d_default_letsencrypt.mustache', EE_ROOT_DIR . '/services/nginx-proxy/vhost.d/default' );
		$challange_dir = EE_ROOT_DIR . '/services/nginx-proxy/html/.well-known/acme-challenge';
		$fs->mkdir( $challange_dir );
		reload_global_nginx_proxy();

		$this->load_certificates( $domain );
		$command = "acme.sh --renew -d $domain" . ( $force ? ' --force' : '' );
		$res = $this->exec( $command, [], true );
		$this->unload_certificates( $domain );

		// Cleanup for http based challenge files
		$fs->remove( $challange_dir );
		$fs->remove( EE_ROOT_DIR . '/services/nginx-proxy/vhost.d/default' );

		$res ? reload_global_nginx_proxy() : \EE::error( "Failed to renew certificate for domain $domain" );
		return $res;
	}

	/**
	 * Lists all domains available to acme.sh
	 *
	 * @return false|string[] List of available domains
	 *
	 * @since 3.3.0
	 */
	public function list_available_domains() : array {
		//$command = 'docker exec service_global-acme-sh-daemon sh -c \'acme.sh --list | sed -e 1d -e s/\ .*$// | xargs echo\'';
		$command = 'docker exec service_global-acme-sh-daemon sh -c \'ls /certs-vol/*.conf | xargs -n 1 basename | sed -e s/.conf//\'';

		\EE\Utils\check_proc_available( 'exec' );

		\EE::debug( '-----------------------' );
		\EE::debug( "COMMAND: $command" );

		$proc    = \EE\Process::create( $command, null, null );
		$results = $proc->run();
		if ( ! empty( $results->stdout ) ) {
			\EE::debug( "STDOUT: $results->stdout" );
		}
		if ( ! empty( $results->stderr ) ) {
			\EE::debug( "STDERR: $results->stderr" );
		}
		\EE::debug( "RETURN CODE: $results->return_code" );
		\EE::debug( '-----------------------' );

		return array_filter( explode( ' ', $results->stdout ) );
	}

	/**
	 * Cleanup created challenge files and specific rule sets for it.
	 *
	 * @returns bool ``true`` on success, ``false`` on failure.
	 *
	 * @since 3.3.0
	 */
	public function cleanup() : bool {
		$exists = \EE::exec(
			'
			docker ps | grep service_global-acme-sh-daemon
		'
		);
		if ( ! $exists ) {
			return true;
		}
		return \EE::exec( 'docker stop service_global-acme-sh-daemon' );
	}

	/**
	 * Removes the domain from acme.sh
	 *
	 * @param string $domain Domain to be removed.
	 *
	 * @return bool ``true`` on success, ``false`` on failure.
	 *
	 * @since 3.3.0
	 */
	private function remove_certificate( string $domain ) : bool {
		$command = "acme.sh --remove -d $domain\n
		rm /certs-vol/$domain.*";
		return $this->exec( $command );
	}
}

