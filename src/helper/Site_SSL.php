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
	 */
	private $certificate_authority = 'letsencrypt';
	private $conf_dir;

	function __construct() {
		$this->conf_dir = EE_ROOT_DIR . '/services/nginx-proxy/acme-conf';
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
	 */
	public function init() : bool {
		return \EE::exec( $this->acme_sh_init ) &&
			\EE::exec(
				'expor   t LE_CONFIG_HOME=/acme-home && acme.sh --set-default-ca --server ' . $this-> certificate_authority
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
	 ** certificate home and after onverting them to required format.
	 *
	 * @param string $domain Domain for which certificates are to be unloaded.
	 *
	 * @return bool ``true`` on success, ``false`` on failure.
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
	 * @return bool ``true`` on success, ``false`` on failiure
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
	 * @return bool ``true`` on success, ``false`` on failiure
	 */
	public function register( $email ) : bool {
		return $this->exec(
			'acme.sh --register-account --email ' . $email
		);
	}

	public function revoke_certificates( array $domains ) {
		// TODO
	}

	/**
	 * Check expiry if a certificate is already expired.
	 *
	 * @param string $domain
	 */
	public function is_already_expired( $domain ) {
		// TODO
	}

	/**
	 * Check expiry of a certificate.
	 *
	 * @param string $domain
	 */
	public function is_renewal_necessary( $domain ) {
		// TODO
	}

	public function issue_certificate( $domains ) {
		// TODO
	}

	public function list_available_domains() {
		// TODO
	}

	/**
	 * Cleanup created challenge files and specific rule sets for it.
	 */
	public function cleanup() {
		\EE::exec( 'docker stop service_global-acme-sh-daemon' );
	}
}

