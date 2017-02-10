<?php

/**
 * @author    jan huang <bboyjanhuang@gmail.com>
 * @copyright 2016
 *
 * @link      https://www.github.com/janhuang
 * @link      http://www.fast-d.cn/
 */

namespace FastD\BasicAuthenticate;

use PDO;

/**
 * Class PdoAuthenticator
 * @package FastD\BasicAuthenticate
 */
class PdoAuthenticator implements AuthenticatorInterface
{
    /**
     * @var PDO
     */
    protected $pdo;

    /**
     * @var string
     */
    protected $table;

    /**
     * @var string
     */
    protected $field;

    /**
     * @var string
     */
    protected $hash;

    /**
     * @var null|array
     */
    protected $user = null;

    /**
     * PdoAuthenticator constructor.
     * @param array $options
     */
    public function __construct(array $options)
    {
        $this->pdo = $options['pdo'];
        $this->table = $options['table'];
        $this->field = $options['field'];
        $this->hash = $options['hash'];
    }

    /**
     * @return mixed
     */
    private function sql()
    {
        $sql =
            "SELECT *
                 FROM {$this->table}
                 WHERE {$this->field} = ?
                 LIMIT 1";

        return preg_replace("!\s+!", " ", $sql);
    }

    /**
     * @return array|null
     */
    public function getUserInfo()
    {
        return $this->user;
    }

    /**
     * @param $user
     * @param $password
     * @return bool
     */
    public function validate($user, $password)
    {
        $this->user = null;

        $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);

        $sql = $this->sql();

        $statement = $this->pdo->prepare($sql);
        $statement->execute([$user]);


        if ($this->user = $statement->fetch(PDO::FETCH_ASSOC)) {
            $isPassed = password_verify($password, $this->user[$this->hash]);
            unset($this->user[$this->hash]);
            return $isPassed;
        }

        return false;
    }
}
