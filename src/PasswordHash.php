<?php

namespace Ayesh\WP_PasswordHash;

use wpdb;
use function __;
use function add_action;
use function apply_filters;
use function class_exists;
use function defined;
use function hash_equals;
use function is_array;
use function md5;
use function password_get_info;
use function password_hash;
use function password_needs_rehash;
use function password_verify;
use function strlen;
use function wp_cache_delete;
use const ABSPATH;
use const PASSWORD_DEFAULT;
use const WP_PASSWORD_HASH_ALGO;
use const WP_PASSWORD_HASH_OPTIONS;
use const WPINC;

final class PasswordHash {
	private $algorithm = PASSWORD_DEFAULT;
	private $algorithm_options = [];
	private $wpdb;
	const TEXT_DOMAIN = 'password-hash';

	public function __construct(wpdb $wpdb) {
		$this->wpdb = $wpdb;
		$this->initializePasswordConfig();
	}

	private function initializePasswordConfig() {
		if (defined('WP_PASSWORD_HASH_ALGO')) {
			$this->algorithm = WP_PASSWORD_HASH_ALGO;

			if (defined('WP_PASSWORD_HASH_OPTIONS') && is_array(WP_PASSWORD_HASH_OPTIONS)) {
				$this->algorithm_options = WP_PASSWORD_HASH_OPTIONS;
			}
			$this->algorithm_options = apply_filters( 'wp_php_password_hash_options', $this->algorithm_options );
		}
	}

	public static function setAdminWarning($message) {
		$message = __($message, self::TEXT_DOMAIN);
		add_action( 'admin_notices', static function () use ($message) {
				print "<div class='notice notice-error'><p>{$message}</p></div>";
			}
		);
	}

	/**
	 * Check the user-supplied password against the hash from the database. Falls
	 *  back to core password hashing mechanism if the password hash if of unknown
	 *  format.
	 *
	 * @global PasswordHash $wp_hasher PHPass object used for checking the password
	 *	against the $hash + $password
	 * @uses PasswordHash::CheckPassword
	 *
	 * @param string     $password Plain text user's password
	 * @param string     $hash     Hash of the user's password to check against.
	 * @param string|int $user_id  Optional. User ID.
	 * @return bool False, if the $password does not match the hashed password
	 *
	 */
	public function checkPassword(string $password, string $hash, $user_id = ''): bool {
		// Check if the hash uses Password API.
		$info = password_get_info($hash);
		if (!empty($info['algo'])) {
			return $this->checkPasswordNative($password, $hash, $user_id);
		}

		// Is it god forbid MD5?
		if ( strlen($hash) <= 32 ) {
			return $this->checkPasswordMD5($password, $hash, $user_id);
		}

		// Fallback to PHPass
		return $this->checkPasswordPHPass($password, $hash, $user_id);
	}

	/**
	 * Hash password using @param string $password Plaintext password
	 *
	 * @return false|string
	 *@see password_hash() function.
	 *
	 */
	public function getHash(string $password) {
		return password_hash($this->preHash($password), $this->algorithm, $this->algorithm_options);
	}

	/**
	 * Sets password hash taken from @param string $password password in plain text.
	 *
	 * @param int $user_id User ID of the user.
	 * @return bool|string
	 *@see wp_hash_password().
	 *
	 */
	public function updateHash(string $password, int $user_id) {
		$hash = $this->getHash($password);
		$fields = [ 'user_pass' => &$hash, 'user_activation_key' => '' ];
		$conditions = [ 'ID' => $user_id ];
		$this->wpdb->update($this->wpdb->users, $fields, $conditions);

		wp_cache_delete( $user_id, 'users' );

		return $hash;
	}

	private function checkPasswordNative($password, $hash, $user_id = '') {
		// Check preHashed password first
		$check = password_verify($this->preHash($password), $hash);
		if( $check === true ) {
			$rehash = password_needs_rehash($hash, $this->algorithm, $this->algorithm_options);
		} else {
			// Fallback password check for previous non pre-hashed password
			$check = password_verify($password, $hash);
			$rehash = true;
		}

		return $this->processPasswordCheck($check, $password, $hash, $user_id, $rehash);
	}

	private function checkPasswordMD5($password, $hash, $user_id = '') {
		$check = hash_equals( $hash, md5( $password ) );
		return $this->processPasswordCheck($check, $password, $hash, $user_id);
	}

	private function checkPasswordPHPass($password, $hash, $user_id = '') {
		global $wp_hasher;

		if ( empty($wp_hasher) ) {
			if( !class_exists('PasswordHash') ) {
				require_once ABSPATH . WPINC . '/class-phpass.php';
			}
			$wp_hasher = new \PasswordHash(8, true);
		}

		$check = $wp_hasher->CheckPassword($password, $hash);
		return $this->processPasswordCheck($check, $password, $hash, $user_id);
	}

	private function processPasswordCheck($check, $password, $hash, $user_id, $rehash = true) {
		if ($check && $user_id && $rehash) {
			$hash = $this->updateHash($password, $user_id);
		}

		return apply_filters( 'check_password', $check, $password, $hash, $user_id );
	}

	/**
	 * Pre-hashes the password before hashing it with the chosen algorithm.
	 *
	 * This method pre-hashes the password based on certain conditions before using the chosen algorithm to hash it.
	 * If the algorithm is CRYPT_BLOWFISH, which has a 72-character limit, the password is pre-hashed using HMAC.
	 * If the calculated entropy of the password is lower than 480, indicating low randomness, it is pre-hashed using HMAC.
	 * If pre-hashing is not required, the method returns null.
	 *
	 * @param string $password The password to pre-hash.
	 * @return string|null Returns the pre-hashed password.
	 */
	private function preHash($password) {
		// bcrypt 72 char limit
		if($this->algorithm === CRYPT_BLOWFISH) return $this->hmac_base64($password);

		// Low calculated entropy
		if($this->calculateEntropy($password) < 480) return $this->hmac_base64($password);

		// Pre-hashing is not required just pepper the password
		return substr($password . SECURE_AUTH_SALT, 0, 4096);
	}

	/**
	* Generates a base64-encoded Hash-based Message Authentication Code (HMAC) using the specified algorithm.
	*
	* This function calculates the HMAC of the provided password using the specified algorithm (default is SHA-512)
	* and the WordPress SECURE_AUTH_SALT as the secret key. It then encodes the result using base64 encoding.
	*
	* @param string $password The password to generate the HMAC for.
	* @param string $algo Optional. The hashing algorithm to use. Default is 'sha512'.
	* @return string|null Returns the base64-encoded HMAC string, or null on failure.
	*/
	private function hmac_base64(string $password, string $algo = 'sha512') {
		// Calculate the HMAC using hash_hmac function
		$hmac = hash_hmac($algo,  $password, SECURE_AUTH_SALT );

		if ($hmac === false) {
			return null; // Return null on failure
		}

		// Encode the HMAC using base64 encoding
		return base64_encode($hmac);
	}

	/**
	* Calculates the entropy of a given password.
	*
	* This function calculates the entropy of the provided password based on the number of unique characters
	* and the length of the password. The entropy is computed using the formula: Entropy = log2(N^L),
	* where N is the number of unique characters and L is the length of the password.
	*
	* @param string $password The password for which to calculate the entropy.
	* @return float The entropy of the password.
	*/
	public function calculateEntropy($password) {
		// Count the number of unique characters in the password
		$uniqueCharacters = count(array_unique(str_split($password)));

		// Calculate the entropy using the formula: Entropy = log2(N^L)
		$entropy = log(pow($uniqueCharacters, strlen($password)), 2);

		return $entropy;
	}
}
