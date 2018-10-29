<?php

namespace AppBundle\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Guard\Authenticator\AbstractFormLoginAuthenticator;
use Symfony\Component\Security\Core\Security;

class LoginFormAuthenticator extends AbstractFormLoginAuthenticator
{
     private $router;

     private $encoder;

     private $security;

     public function __construct(RouterInterface $router, UserPasswordEncoderInterface $encoder)
     {
         $this->router = $router;
         $this->encoder = $encoder;

     }
     public function getCredentials(Request $request)
     {
         $isLoginSubmit = $request->getPathInfo() == '/login_check' && $request->isMethod('POST');
         if (!$isLoginSubmit) {
             // skip authentication
             return;
         }

         //Add your logic here

         $email = $request->request->get('_username');
         $request->getSession()->set(Security::LAST_USERNAME, $email);
         $password = $request->request->get('_password');
         return [
             'username' => $email,
             'password' => $password,
         ];
     }

     public function getUser($credentials, UserProviderInterface $userProvider)
     {
         //Add your logic here

         $email = $credentials['username'];

         return $userProvider->loadUserByUsername($email);
     }

     public function checkCredentials($credentials, UserInterface $user)
     {
         $plainPassword = $credentials['password'];

         //Add your logic here

         if ($this->encoder->isPasswordValid($user, $plainPassword)) {
             return true;
         }
         throw new BadCredentialsException();
     }

     public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
     {
       //Add your logic here

     }

     public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
     {
       //Add your logic here
     }

     protected function getLoginUrl()
     {
         return $this->router->generate('fos_user_security_login');
     }

     protected function getDefaultSuccessRedirectUrl()
     {
         return $this->router->generate('home');
     }

     public function supportsRememberMe()
     {
         return false;
     }


}
