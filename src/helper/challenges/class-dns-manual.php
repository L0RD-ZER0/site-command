<?php

namespace EE\Site\Type\Site_SSL;

use EE\Site\Type\Site_SSL\Base_Challenge;

class DNS_Manual extends Base_Challenge {

	/**
	 * @inheritDoc
	 */
	function solve( string $main_domain, array $san_domains, string $email, bool $force = false ) : bool {
		// TODO: Implement solve() method.
		return false;
	}
}
