<?php

/*
 * This file is part of the HWIOAuthBundle package.
 *
 * (c) Hardware.Info <opensource@hardware.info>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace HWI\Bundle\OAuthBundle\OAuth\ResourceOwner;

use Psr\Http\Message\ResponseInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * AzureB2CResourceOwner
 *
 * @author Baptiste Clavié <clavie.b@gmail.com>
 * @author Tymon Terlikiewicz <tymon@batmaid.com>
 */
class AzureB2CResourceOwner extends GenericOAuth2ResourceOwner
{
    /**
     * {@inheritDoc}
     */
    protected $paths = array(
        'identifier' => 'oid', //'sub' is not supported currently
        'nickname' => 'name',
        'realname' => array('name', 'family_name'),
        'email' => 'emails.0',
        'firstname' => 'name',
        'lastname' => 'family_name',
        'postalCode' => 'postalCode',
        'country' => 'country',
        'city' => 'city',
        'street' => 'streetAddress',
        'state' => 'state',
        'jobTitle' => 'jobTitle',
        'nonce' => 'nonce',
    );

    /**
     * {@inheritDoc}
     */
    public function configure()
    {
        $this->options['access_token_url'] = sprintf($this->options['access_token_url'],
            $this->options['application'],
            $this->options['sign_in_policy']
        );
        $this->options['authorization_url'] = sprintf($this->options['authorization_url'], $this->options['application']);
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthorizationUrl($redirectUri, array $extraParameters = array())
    {
        //nonce is actually not returned as part of id_token, contrary to documentation. But still required
        $nonce = $this->generateNonce();

        return parent::getAuthorizationUrl($redirectUri, $extraParameters + [
                'p' => $this->options['sign_in_policy'],
                'nonce' => $nonce,
                'response_type' => 'code id_token',
                'response_mode' => 'query',
            ]);
    }

    /**
     * @param mixed $response the 'parsed' content based on the response headers
     *
     * @throws AuthenticationException If an OAuth error occurred or no access token is found
     */
    protected function validateResponseContent($response)
    {
        if (isset($response['error_description'])) {
            throw new AuthenticationException(sprintf('OAuth error: "%s"', $response['error_description']));
        }

        if (isset($response['error'])) {
            throw new AuthenticationException(sprintf('OAuth error: "%s"', isset($response['error']['message']) ? $response['error']['message'] : $response['error']));
        }

        if (!isset($response['id_token'])) {
            throw new AuthenticationException('Not a valid id token.');
        }
    }

    /**
     * {@inheritDoc}
     */
    public function refreshAccessToken($refreshToken, array $extraParameters = array())
    {
        $nonce = $this->generateNonce();
        return parent::refreshAccessToken($refreshToken, $extraParameters + [
                'p' => $this->options['sign_in_policy'],
                'nonce' => $nonce,
                'response_type' => 'code id_token',
                'response_mode' => 'query',
            ]);
    }

    protected function getResponseContent(ResponseInterface $rawResponse)
    {
        $response = parent::getResponseContent($rawResponse);
        //The id_token should be used as the access_token according to
        //https://azure.microsoft.com/en-us/documentation/articles/active-directory-b2c-reference-oidc/
        if (isset($response['id_token'])) {
            //the token is not set in case of configuration errors
            $response["access_token"] = $response['id_token'];
        }
        return $response;
    }

    /**
     * {@inheritDoc}
     */
    public function getUserInformation(array $accessToken, array $extraParameters = array())
    {
        // from http://stackoverflow.com/a/28748285/624544
        list(, $jwt) = explode('.', $accessToken['id_token'], 3);

        // if the token was urlencoded, do some fixes to ensure that it is valid base64 encoded
        $jwt = str_replace(array('-', '_'), array('+', '/'), $jwt);

        // complete token if needed
        switch (strlen($jwt) % 4) {
            case 0:
                break;

            case 2:
            case 3:
                $jwt .= '=';
                break;

            default:
                throw new \InvalidArgumentException('Invalid base64 format sent back');
        }

        $response = parent::getUserInformation($accessToken, $extraParameters);
        $response->setData(base64_decode($jwt));

        return $response;
    }

    /**
     * {@inheritDoc}
     */
    protected function configureOptions(OptionsResolver $resolver)
    {
        parent::configureOptions($resolver);

        $resolver->setRequired(array('sign_in_policy', 'application'));

        $resolver->setDefaults(array(
            'infos_url' => 'https://graph.windows.net/contosob2c.onmicrosoft.com/users/?api-version=1.6',
            'authorization_url' => 'https://login.microsoftonline.com/%s/oauth2/v2.0/authorize',
            'access_token_url' => 'https://login.microsoftonline.com/%s/oauth2/v2.0/token?p=%s',
            'scope' => 'openid offline_access',
            'user_response_class' => 'HWI\Bundle\OAuthBundle\OAuth\Response\AzureB2CUserResponse',
            'api_version' => 'v1.0',
            'csrf' => true
        ));
    }
}
