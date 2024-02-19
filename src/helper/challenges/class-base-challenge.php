<?php

namespace EE\Site\Type\Site_SSL;

abstract class BaseChallenge {
	const HTTP = 'http';
	const DNS_MANUAL = 'dns-manual';
	const DNS_CLOUDFLARE = 'dns-cloudflare';

	/**
	 * A challenge has to solve / validate itself.
	 *
	 * $domains string[] The domains for which the challenge has to be solved.
	 *
	 * @returns bool True if the challenge was solved successfully, false otherwise.
	 *
	 * @since 4.0.0
	 */
	abstract function solve( array $domains ) : bool;
};
