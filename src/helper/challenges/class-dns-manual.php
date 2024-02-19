<?php

namespace EE\Site\Type\Site_SSL;

use EE\Site\Type\Site_SSL\BaseChallenge;

class DNS_Manual extends BaseChallenge {

	/**
	 * @inheritDoc
	 */
	function solve( string $main_domain, array $san_domains, string $email, bool $force = false ) : bool {
		// TODO: Implement solve() method.
		return false;
	}
}
