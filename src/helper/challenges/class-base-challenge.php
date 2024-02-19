<?php

namespace EE\Site\Type\Site_SSL;

use EE\Site\Type\Site_SSL;

abstract class Base_Challenge {

	protected $client;

	public function __construct( Site_SSL $client ) {
		$this->client = $client;
	}

	/**
	 * Solves the challenge for the given domain
	 *
	 * @param string $main_domain The main domain for which the challenge has to be solved.
	 * @param string[] $san_domains The list of SAN domains for which the challenge has to be solved.
	 * @param string $email The email address to be used for the ACME account.
	 * @param bool $force Whether to force the challenge to be solved again.
	 *
	 * @returns bool True if the challenge was solved successfully, false otherwise.
	 *
	 * @since 4.0.0
	 */
	abstract function solve( string $main_domain, array $san_domains, string $email, bool $force = false ) : bool;
};
