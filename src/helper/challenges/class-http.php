<?php

namespace EE\Site\Type\Site_SSL;

use EE\Site\Type\Site_SSL\Base_Challenge;
use function EE\Site\Utils\reload_global_nginx_proxy;

class HTTP extends Base_Challenge {

	/**
	 * @inheritDoc
	 */
	function solve( string $main_domain, array $san_domains, string $email, bool $force = false ) : bool {
		if ( ! $this->client->init() ) {
			\EE::error( "Couldn't start the service for acme.sh" );
			return false;
		}
		$san_domains = array_unique( $san_domains );
		$key = array_search( $main_domain, $san_domains );
		if ( false !== $key ) {
			unset( $san_domains[ $key ] );
		}
		$san_domains_str = '';
		foreach ( $san_domains as $san ) {
			if ( empty( $san ) ) {
				continue;
			}
			$san_domains_str = $san_domains_str . " -d $san";
		}
		$fs = new \Symfony\Component\Filesystem\Filesystem();
		try {
			$fs->copy( SITE_TEMPLATE_ROOT . '/vhost.d_default_letsencrypt.mustache', EE_ROOT_DIR . '/services/nginx-proxy/vhost.d/default' );
			$challange_dir = EE_ROOT_DIR . '/services/nginx-proxy/html/.well-known/acme-challenge';
			$fs->mkdir( $challange_dir );
			reload_global_nginx_proxy();
			$res = $this->client->exec(
				'echo LE_CONFIG_HOME=$LE_CONFIG_HOME;'
				. 'echo LE_WORKING_DIR=$LE_WORKING_DIR;'
				. 'echo DEFAULT_ACME_SERVER=$DEFAULT_ACME_SERVER;'
				. "acme.sh --issue --webroot /webroot -d $main_domain"
				. $san_domains_str
				. " --email $email"
				. ( $force ? ' --force' : ''),
				[], true
			);
			if ( ! $res ) {
				$this->client->cleanup();
				\EE::error( 'Failed to issue SSL certificate' );
				return false;
			}
			$fs->remove( $challange_dir );
			$fs->remove( EE_ROOT_DIR . '/services/nginx-proxy/vhost.d/default' );
			reload_global_nginx_proxy();
			\EE::success( 'SSL certificate has been successfully issued' );
		} catch ( \Exception $e ) {
			$this->client->cleanup();
			\EE::debug( 'Exception Encountered:' . $e->getMessage() );
			\EE::error( 'Failed to verify SSL certificate for ' . $main_domain );
			return false;
		}
		if ( ! $this->client->unload_certificates( $main_domain ) ) {
			$this->client->cleanup();
			\EE::error( "Couldn't unload produced certificates into the volume" );
			return false;
		}
		$this->client->cleanup();
		return true;
	}
}
