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
	private $acme_sh_init = 'docker run --rm --name service_global-acme-sh-daemon -v "global-nginx-proxy_certs:/certs-vol" -d neilpang/acme.sh daemon';
	private $acme_sh = 'docker exec service_global-acme-sh-daemon sh -c';
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
	 * @since 2.2.0
	 */
	private $certificate_authority = 'letsencrypt';
	private $challenges;
	private $conf_dir;

	function __construct() {
		$this->conf_dir = EE_ROOT_DIR . '/services/nginx-proxy/acme-conf';
		$this->challenges = [
			ChallengeType::DNS_MANUAL   => new Site_SSL\DNS_Manual(),
			ChallengeType::DNS_CF       => new Site_SSL\DNS_CF(),
			ChallengeType::HTTP         => new Site_SSL\HTTP(),
		];
	}


	/**
	 * Function to execute an acme.sh command in its docker container
	 *
	 * @param string $command Command to be executed.
	 *
	 * @return bool ``true`` on success, ``false`` on failure.
	 *
	 * @since 2.2.0
	 *
	 */
	private function exec( string $command ) : bool {
		$command = str_replace( "'", "\'", $command );
		$command = $this->acme_sh . "'" . $command . "'";
		\EE::debug( 'Executing: ' . $command );
		return \EE::exec( $command );
	}

	/**
	 * Starts acme.sh service container in daemon mode
	 *
	 * @return bool ``true`` on success, ``false`` on failure
	 *
	 * @since 2.2.0
	 */
	public function init() : bool {
		return \EE::exec( $this->acme_sh_init ) &&
			\EE::exec(
				'export LE_CONFIG_HOME=/acme-home && acme.sh --set-default-ca --server ' . $this-> certificate_authority
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
	 * @since 2.2.0
	 */
	private function load_certificates( string $domain ) : bool {
		return $this->exec(
			"
			mkdir -p /acme-home/$domain;
			cp /certs-vol/$domain.* /acme-home/$domain;
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
	 * @since 2.2.0
	 */
	private function unload_certificates( string $domain ) : bool {
		return $this->convert_certificates( $domain ) &&
			$this->exec(
				"
				mv /acme-home/$domain/$domain.crt /certs-vol/$domain.crt;
				mv /acme-home/$domain/$domain.chain.pem /certs-vol/$domain.chain.pem;
				mv /acme-home/$domain/$domain.key /certs-vol/$domain.key;
				mv /acme-home/$domain/$domain.conf /certs-vol/$domain.conf;
			"
			);
	}

	/**
	 * Converts the output certificates from acme.sh to our required format
	 *
	 * @param string $domain domain for certificate
	 *
	 * @return bool ``true`` on success, ``false`` on failure
	 *
	 * @since 2.2.0
	 */
	private function convert_certificates( string $domain ) : bool {
		return $this->exec(
			"
			cp /acme-home/$domain/fullchain.cer /acme-home/$domain/$domain.chain.pem;
			cp /acme-home/$domain/$domain.cer /acme-home/$domain/$domain.pem;
		"
		);
	}


	/**
	 * Function to register mail to letsencrypt.
	 *
	 * @param string $email Mail id to be registered.
	 *
	 * @return bool ``true`` on success, ``false`` on failure
	 *
	 * @since 2.2.0
	 */
	public function register( string $email ) : bool {
		return $this->exec(
			'acme.sh --register-account --email ' . $email
		);
	}

	/**
	 * @param array $domains Domains for which certificate is to be revoked.
	 * @param int $reason Reason for revoking certificate
	 *
	 * @return bool ``true`` on success, ``false`` on failure
	 *
	 * @since 2.2.0
	 */
	public function revoke_certificates( array $domains, int $reason = 0 ) : bool {
		foreach ( $domains as $domain ) {
			$res = $this->load_certificates( $domain );
			if ( ! $res ) {
				\EE::debug( "Couldn't load certificate for $domain" );
				return false;
			}
			$res = $this->exec( "acme.sh --revoke -d $domain --reason $reason" );
			if ( ! $res ) {
				\EE::debug( "Couldn't revoke certificate for $domain" );
				return false;
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
	 * @since 2.2.0
	 */
	public function is_already_expired( string $domain ) : bool {
		return $this->exec(
			"
				timestamp=\"$(acme.sh -d $domain --info | grep Le_NextRenewTime= | sed -e s/Le_NextRenewTime=\'// -e s/\'//')
				echo -e \"Timestamp: \$timestamp\nNow: $(date +%s)\"
				if [ \$timestamp -lt $(date +%s) ]; then  # Timestamp less than now, i.e. date has gone by
					echo Certificate has Expired;
					exit 0;  # true
				else
					echo Certificate has Not Expired;
		 			exit 1;  # false
				fi
			"
		);
	}

	/**
	 * Check expiry of a certificate.
	 *
	 * @param string $domain Domain for which certificate is to be checked.
	 *
	 * @returns bool ``true`` if certificate should be renewed, ``false`` otherwise.
	 *
	 * @since 2.2.0
	 */
	public function is_renewal_necessary( string $domain ) : bool {
		// Check if certificate expires in next 30 days or so
		return $this->exec(
			"
				timestamp=\"$(acme.sh -d $domain --info | grep Le_NextRenewTime= | sed -e s/Le_NextRenewTime=\'// -e s/\'//')
				echo -e \"Timestamp: \$timestamp\nNow: $(date +%s)\"
				if [ \$timestamp -lt $(date -d 30days +%s) ]; then  # Timestamp less than now, i.e. date has gone by
					echo Renewal is Necessary;
					exit 0;  # true
				else
					echo Renewal is not necessary;
					exit 1;  # false
				fi
			"
		);
	}

	/**
	 * Issue a certificate for a domain
	 *
	 * @param string[] $domains Domains for which certificate is to be issued.
	 *
	 * @return bool ``true`` on success, ``false`` on failure.
	 *
	 * @since 2.2.0
	 */
	public function issue_certificate( array $domains ) : bool {
		// TODO
		return false;
	}

	/**
	 * Lists all domains available to acme.sh
	 *
	 * @return false|string[] List of available domains
	 *
	 * @since 2.2.0
	 */
	public function list_available_domains() : array {
		$command = 'acme.sh --list | sed -e 1d -e s/\ .*$// | xargs echo';

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

		return array_filter( explode( ' ', $results['stdout'] ) );
	}

	/**
	 * Cleanup created challenge files and specific rule sets for it.
	 */
	public function cleanup() {
		\EE::exec( 'docker stop service_global-acme-sh-daemon' );
	}
}

