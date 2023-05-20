<?php

try {
    # Cargar la mini librería
    require_once('./jwt.class.php');

    # Invocar a la mini librería
    $jwt = new MiniJWT();

    # Definir la clave de seguridad (requerido para firmar y validar los tokens)
    $jwt->setPrivateKey('daasdasdasdasd');    

    # Definir el payload (los datos que se guardarán en el token)
    # En caso de pasar el item 'exp', se realizará un control del timestamp de este para saber si aún es vigente o no
    $jwt->setPayload([
        'id'   => '13091823',
        'name' => 'Fula Nito',
        'exp'  => '2023-05-19 10:25',
    ]);

    # El token generado
    $jwt_token = $jwt->generateToken();
    var_dump($jwt_token);

    # Validar el token
    $degenerated = $jwt->getContentFromToken($jwt_token);

    var_dump($degenerated);
} catch (\Throwable $th) {
    var_dump($th->getMessage());
}
