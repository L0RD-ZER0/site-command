<?php

namespace EE\Site\Type\Site_SSL;

use EE\Site\Type\Site_SSL\Base_Challenge;
use function EE\Utils\get_config_value;

class DNS_CF extends Base_Challenge {

	/**
	 * @inheritDoc
	 */
	function solve( string $main_domain, array $san_domains, string $email, bool $force = false ) : bool {
		$cf_token = get_config_value( 'cloudflare_api_key' );
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
		$res = $this->client->exec(
			'echo LE_CONFIG_HOME=$LE_CONFIG_HOME;'
			. 'echo LE_WORKING_DIR=$LE_WORKING_DIR;'
			. 'echo DEFAULT_ACME_SERVER=$DEFAULT_ACME_SERVER;'
			. "export CF_Token=\"$cf_token\";"
			. "acme.sh --issue --test --dns dns_cf -d $main_domain"
			. $san_domains_str
			. " --email $email"
			. ( $force ? ' --force' : ''),
			[ $cf_token ], true
		);
		if ( ! $res ) {
			\EE::error( "Couldn't issue certificate from acme.sh" );
			return false;
		}
		if ( ! $this->client->unload_certificates( $main_domain ) ) {
			\EE::error( "Couldn't unload produced certificates into the volume" );
			return false;
		}
		$this->client->cleanup();
		return true;
	}
}
