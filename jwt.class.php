<?php
/**
 * Mini librería para generar/validar tokens JWT
 *
 * @author     KuroNeko
 * @license    🦄 Thei licensed this
 * @version    Release: 1.0.0
 */ 

class MiniJWT {

    public $key;
    public $payload;

    function __construct() {}

    public function setPrivateKey($key) {
        $this->key = $key;
    }

    public function setPayload($payload = []) {
        if(empty($payload)) { throw new Exception('No se han recibido datos'); }
        if(!is_array($payload) && !is_object($payload)) { throw new Exception('Se espera recibir un array u objeto'); }

        $this->payload = $payload;
    }

    public function generateToken() {
        if(is_null($this->key) || empty(trim($this->key))) { throw new Exception('Por favor defina la clave de seguridad'); }

        $header    = $this->base64UrlEncode(json_encode([ 'alg' => 'HS256', 'typ' => 'JWT' ]));
        $payload   = $this->base64UrlEncode(json_encode($this->payload));
        $signature = $this->base64UrlEncode(hash_hmac('sha256', "{$header}.{$payload}", $this->key, true));
        $jwt_token = "{$header}.{$payload}.{$signature}";
        return $jwt_token;
    }

    public function getContentFromToken($token) {
        if(is_null($this->key) || empty(trim($this->key))) { throw new Exception('Por favor defina la clave de seguridad'); }

        $token_parts = explode('.', $token);

        if(count($token_parts) != 3) {
            throw new Exception('Token no válido; no cuenta con la estructura correcta');
        }

        $header    = $this->base64UrlDecode($token_parts[0]);
        $payload   = $this->base64UrlDecode($token_parts[1]);
        $signature = $this->base64UrlDecode($token_parts[2]);
    
        $expectedSignature = hash_hmac('sha256', "{$token_parts[0]}.{$token_parts[1]}", $this->key, true);

        if(!hash_equals($signature, $expectedSignature)) {
            throw new Exception('La firma no es válida');
        }

        $header  = json_decode($header, true);
        $payload = json_decode($payload, true);

        if(!$header || !$payload) {
            throw new Exception('No se pudo decodificar la cabecera o el contenido');
        }

        if(isset($payload['exp']) && date('Y-m-d H:i:s') >= $payload['exp']) {
            throw new Exception('El token ya ha expirado');
        }

        return $payload;
    }

    private function base64UrlEncode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function base64UrlDecode($data) {
        $base64 = base64_decode(strtr($data, '-_', '+/'));
        return ($base64 === false) ? false : $base64;
    }
}

?>
