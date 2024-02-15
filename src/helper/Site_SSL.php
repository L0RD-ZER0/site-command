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

	private $conf_dir;

	function __construct() {
		$this->conf_dir = EE_ROOT_DIR . '/services/nginx-proxy/acme-conf';
	}


	public function init() {
		// TODO
	}

	/**
	 * Function to register mail to letsencrypt.
	 *
	 * @param string $email Mail id to be registered.
	 *
	 * @throws \Exception
	 * @return bool Success.
	 */
	public function register( $email ) {
		// TODO
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
		// TODO
	}

	private function cer_to_pem( $cer, $csr ) {
		// TODO
	}
}

