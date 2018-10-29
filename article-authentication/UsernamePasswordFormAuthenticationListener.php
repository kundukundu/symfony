<?php

namespace AppBundle\EventListener;

use Symfony\Component\Security\Http\Firewall\UsernamePasswordFormAuthenticationListener as BaseListener;
use Symfony\Component\Form\Extension\Csrf\CsrfProvider\CsrfProviderAdapter;
use Symfony\Component\Form\Extension\Csrf\CsrfProvider\CsrfProviderInterface;
use Symfony\Component\HttpFoundation\Request;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\ParameterBagUtils;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\InvalidArgumentException;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;


class UsernamePasswordFormAuthenticationListener extends BaseListener

{
  protected $csrfTokenManager;

    public function __construct(TokenStorageInterface $tokenStorage, AuthenticationManagerInterface $authenticationManager, SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, $providerKey, AuthenticationSuccessHandlerInterface $successHandler, AuthenticationFailureHandlerInterface $failureHandler, array $options = array(), LoggerInterface $logger = null, EventDispatcherInterface $dispatcher = null, $csrfTokenManager = null)
  {
    parent::__construct($tokenStorage, $authenticationManager, $sessionStrategy, $httpUtils, $providerKey, $successHandler, $failureHandler, array_merge(array(
        'username_parameter' => '_username',
        'password_parameter' => '_password',
        'csrf_parameter' => '_csrf_token',
        'csrf_token_id' => 'authenticate',
        'post_only' => true,
    ), $options), $logger, $dispatcher);

    $this->csrfTokenManager = $csrfTokenManager;
   }

    /**
     * {@inheritdoc}
     */
    protected function attemptAuthentication(Request $request)
    {
        if (null !== $this->csrfTokenManager) {
            $csrfToken = ParameterBagUtils::getRequestParameterValue($request, $this->options['csrf_parameter']);

            if (false === $this->csrfTokenManager->isTokenValid(new CsrfToken($this->options['csrf_token_id'], $csrfToken))) {
                throw new InvalidCsrfTokenException('Invalid CSRF token.');
            }
        }

        if ($this->options['post_only']) {
            $username = $this->secureRip(ParameterBagUtils::getParameterBagValue($request->request, $this->options['username_parameter']));
        } else {
            $username = $this->secureRip(ParameterBagUtils::getRequestParameterValue($request, $this->options['username_parameter']));
            $password = ParameterBagUtils::getRequestParameterValue($request, $this->options['password_parameter']);
        }

        if (strlen($username) > Security::MAX_USERNAME_LENGTH) {
            throw new BadCredentialsException('Invalid username.');
        }

        $request->getSession()->set(Security::LAST_USERNAME, $username);

        return $this->authenticationManager->authenticate(new UsernamePasswordToken($username, $password, $this->providerKey));
    }


    /**
    * Rips all whitespace
    */
    private function secureRip(string $str): string {
      $arr = str_split($str, 1);
      $retStr = '';
      foreach ($arr as $char) {
        $retStr .= trim($char);
      }
      return $retStr;
    }

}
