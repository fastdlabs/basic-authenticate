<?php

/**
 * @author    jan huang <bboyjanhuang@gmail.com>
 * @copyright 2016
 *
 * @link      https://www.github.com/janhuang
 * @link      http://www.fast-d.cn/
 */

namespace FastD\BasicAuthenticate;

/**
 * Class ArrayAuthenticator
 * @package FastD\BasicAuthenticate
 */
class PhpAuthenticator implements AuthenticatorInterface
{
    /**
     * @var array
     */
    protected $users;

    /**
     * ArrayAuthenticator constructor.
     * @param array $user
     */
    public function __construct(array $user)
    {
        $this->users = $user;
    }

    /**
     * @param $password
     * @return bool
     */
    public function isHash($password)
    {
        return preg_match('/^\$(2|2a|2y)\$\d{2}\$.*/', $password) && (strlen($password) >= 60);
    }

    /**
     * @return null
     */
    public function getUserInfo()
    {
        return null;
    }

    /**
     * @param $user
     * @param $password
     * @return bool
     */
    public function validate($user, $password)
    {
        /* Unknown user. */
        if (!isset($this->users[$user])) {
            return false;
        }

        if ($this->isHash($this->users[$user])) {
            /* Hashed password. */
            return password_verify($password, $this->users[$user]);
        } else {
            /* Cleartext password. */
            return $this->users[$user] === $password;
        }
    }
}
