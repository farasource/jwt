<?php

/*
 * Copyright Farasource (Abbas Ghasemi), 2022.
 * https://farasource.com
 *
 * https://github.com/farasource/jwt
 */

class JWT
{
    private string $type = 'JWT';
    private array $algorithms = [
        'HS256' => 'SHA256',
        'HS384' => 'SHA384',
        'HS512' => 'SHA512'
    ];
    private string $def_alg;
    private ?string $key = null;

    private string $header_payload;
    private ?array $header = null;
    private ?array $payload = null;
    private string $signature;

    /**
     * JWT constructor.
     * @param string|null $key
     * @param string $def_alg
     */
    private function __construct(?string $key, string $def_alg)
    {
        $this->setKey($key);
        if (isset($this->algorithms[$def_alg])) {
            $this->def_alg = $def_alg;
        } else {
            $this->def_alg = 'HS256';
        }
    }

    private static JWT $jwt;

    public static function newJWT(?string $key = null, string $def_alg = 'HS256'): JWT
    {
        if (!isset(self::$jwt)) {
            self::$jwt = new JWT($key, $def_alg);
        }
        return self::$jwt;
    }

    public function verifyJustSyntax(?string $jwt): bool
    {
        if (empty($jwt)) return false;

        $parts = explode('.', $jwt);

        if (count($parts) != 3) return false;

        $this->header = json_decode($this->base64Decode($parts[0]), true);
        $this->payload = json_decode($this->base64Decode($parts[1]), true);
        $this->signature = $this->base64Decode($parts[2]);

        if (empty($this->header['typ']) || empty($this->header['alg']) ||
            $this->header['typ'] != $this->type || !isset($this->algorithms[$this->header['alg']]) ||
            !is_array($this->payload) || empty($this->signature)) {
            $this->reset();
            return false;
        }
        $this->header_payload = "$parts[0].$parts[1]";
        return true;
    }

    public function verifySign(?string $jwt = null): bool
    {
        if (empty($this->key)) return false;
        if (empty($jwt)) {
            if ($this->header === null) return false;
        } else {
            $res = $this->verifyJustSyntax($jwt);
            if (!$res) return false;
        }
        $check = $this->checkSignature();
        if (!$check) $this->reset();
        return $check;
    }

    public function setKey(?string $key, bool $decode = false): void
    {
        if (!empty($key) && strlen($key) >= 32)
            $this->key = $decode ? $this->base64Decode($key) : $key;
    }

    public function addRule(string $key, $value): void
    {
        $this->payload[$key] = $value;
    }

    public function removeRule(string $key): void
    {
        if (isset($this->payload[$key])) {
            unset($this->payload[$key]);
        }
    }

    public function getRule(string $key)
    {
        if (isset($this->payload[$key])) {
            return $this->payload[$key];
        }
        return false;
    }

    public function getJWT(): string
    {
        if (empty($this->key)) return '';
        $this->checkJWT();
        list($header, $payload) = array($this->base64Encode(json_encode($this->header)),
            $this->base64Encode(json_encode($this->payload)));
        $signature = $this->base64Encode($this->sign("$header.$payload"));
        return "$header.$payload.$signature";
    }

    private function base64Encode(string $message): string
    {
        return str_replace('=', '', strtr(base64_encode($message), '+/', '-_'));
    }

    private function base64Decode(string $message): string
    {

        if ($padding = strlen($message) % 4) {
            $padding = 4 - $padding;
            $message .= str_repeat('=', $padding);
        }

        $str = base64_decode(strtr($message, '-_', '+/'));
        if (empty($str)) return '';
        return $str;
    }

    private function checkSignature(): bool
    {
        return $this->sign($this->header_payload) === $this->signature;
    }

    private function sign($plain): string
    {
        return hash_hmac($this->algorithms[$this->header['alg']], $plain, $this->key, true);
    }

    private function reset()
    {
        $this->header = null;
        $this->payload = null;
    }

    private function checkJWT(): void
    {
        if ($this->header === null) {
            $this->header = [
                'alg' => $this->def_alg,
                'typ' => $this->type
            ];
        }
        if ($this->payload === null) {
            $this->payload = [
                'iss' => 'User',
                'iat' => time(),
                'exp' => time() + 24 * 60 * 60,
            ];
        }
    }
}
