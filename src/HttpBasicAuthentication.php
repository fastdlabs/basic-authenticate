<?php
/**
 * @author    jan huang <bboyjanhuang@gmail.com>
 * @copyright 2016
 *
 * @link      https://www.github.com/janhuang
 * @link      http://www.fast-d.cn/
 */

namespace FastD\BasicAuthenticate;


use FastD\Http\Response;
use FastD\Middleware\DelegateInterface;
use FastD\Middleware\Middleware;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use SplStack;

/**
 * Class HttpBasicAuthentication
 * @package FastD\BasicAuthenticate
 */
class HttpBasicAuthentication extends Middleware
{
    const ENVIRONMENT = 'HTTP_AUTHORIZATION';
    const REALM = 'Protected';

    /**
     * @var SplStack
     */
    protected $rules;

    /**
     * @var AuthenticatorInterface
     */
    protected $authenticator;

    /**
     * @var array
     */
    protected $options = [
        'secure' => false,
        'relaxed' => [
            'localhost',
            '127.0.0.1'
        ],
        'authenticator' => null,
    ];

    /**
     * HttpBasicAuthentication constructor.
     * @param array $options
     */
    public function __construct(array $options = [])
    {
        if (!isset($options['authenticator'])) {
            throw new RuntimeException('Authenticator or users is not defined');
        }

        $this->authenticator = new $options['authenticator']['class']($options['authenticator']['params']);

        $this->options = array_merge($this->options, $options);
    }

    /**
     * @param ServerRequestInterface $request
     * @param DelegateInterface $delegate
     * @return ResponseInterface
     */
    public function handle(ServerRequestInterface $request, DelegateInterface $delegate)
    {
        // php fpm or cli
        $server = $request->getServerParams();
        // swoole http server
        if ($request->hasHeader('authorization')) {
            $server[HttpBasicAuthentication::ENVIRONMENT] = $request->getHeaderLine('authorization');
        }

        if ('https' !== ($scheme = $request->getUri()->getScheme())
            && true === $this->options['secure']) {
            if (!in_array($request->getUri()->getHost(), $this->options['relaxed'])) {
                throw new RuntimeException(sprintf(
                    'Insecure use of middleware over %s denied by configuration.',
                    strtoupper($scheme)
                ));
            }
        }

        $user = false;
        $password = false;

        if (isset($server[HttpBasicAuthentication::ENVIRONMENT])) {
            if (preg_match('/Basic\s+(.*)$/i', $server[HttpBasicAuthentication::ENVIRONMENT], $matches)) {
                list($user, $password) = explode(':', base64_decode($matches[1]), 2);
            }
        }  else if (!empty($server))  {
            if (isset($server['PHP_AUTH_USER'])) {
                $user = $server['PHP_AUTH_USER'];
            }
            if (isset($server['PHP_AUTH_PW'])) {
                $password = $server['PHP_AUTH_PW'];
            }
        } else {
            $userInfo = $request->getUri()->getUserInfo();
            if (false !== strpos($userInfo, ':')) {
                list($user, $password) = explode(':', $userInfo);
            }
        }

        if (false === $this->authenticator->validate($user, $password)) {
            $response = isset($this->options['response']['class']) ? $this->options['response']['class'] : Response::class;
            $data = isset($this->options['response']['data']) ? $this->options['response']['data'] : Response::$statusTexts[Response::HTTP_UNAUTHORIZED];
            return (new $response($data))
                ->withStatus(Response::HTTP_UNAUTHORIZED)
                ->withHeader('WWW-Authenticate', sprintf('Basic realm=\'%s\'', HttpBasicAuthentication::REALM));
        }

        return $delegate->process($request);
    }

    /**
     * @return AuthenticatorInterface
     */
    public function getAuthenticator()
    {
        return $this->authenticator;
    }

    /**
     * Get the secure flag
     *
     * @return boolean
     */
    public function isSecure()
    {
        return $this->options['secure'];
    }

    /**
     * Get hosts where secure rule is relaxed
     *
     * @return array
     */
    public function getRelaxed()
    {
        return $this->options['relaxed'];
    }
}
