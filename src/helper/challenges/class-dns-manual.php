<?php

namespace EE\Site\Type\Site_SSL;

use EE\Site\Type\Site_SSL\Base_Challenge;

class DNS_Manual extends Base_Challenge {

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
		$res = $this->client->exec(
			'echo LE_CONFIG_HOME=$LE_CONFIG_HOME;'
			. 'echo LE_WORKING_DIR=$LE_WORKING_DIR;'
			. 'echo DEFAULT_ACME_SERVER=$DEFAULT_ACME_SERVER;'
			. "acme.sh --issue --dns -d $main_domain"
			. ' --yes-I-know-dns-manual-mode-enough-go-ahead-please'
			. $san_domains_str
			. " --email $email"
			. ( $force ? ' --force' : '')
			. ' || [ $? -eq 3 ]',
			[], true
		);
		if ( ! $res ) {
			\EE::error( "Couldn't issue certificate from acme.sh" );
			$this->client->cleanup();
			return false;
		}
		\EE::input( "Please create a TXT record for _acme-challenge.$main_domain with the value shown above, and press enter to continue" );
		$res = $this->client->exec(
			"acme.sh --renew --dns -d $main_domain --yes-I-know-dns-manual-mode-enough-go-ahead-please"
		);
		if ( ! $res ) {
			\EE::error( 'Issue in challenge completion. Please clear your DNS records and try again.' );
			$this->client->cleanup();
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
