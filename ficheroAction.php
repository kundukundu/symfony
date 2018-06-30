<?php

//...
public function ficheroAction($nobreFichero)
{
   $kernel = $this->get('kernel');
   $path = $kernel->locateResource('@AppBundle/Resources/ficheros/'.$nombreFichero);

   $response = new BinaryFileResponse($path)
   $response->headers->set('Content-Type', 'application/pdf');
   /** Cargar el fichero en el navegador
   * Utiliza ResponseHeaderBag::DISPOSITION_ATTACHMENT para guardar el fichero como adjunto
   */
   $response->setContentDisposition(
      ResponseHeaderBag::DISPOSITION_INLINE,
      $nombreFichero
   );

   return $response;
}
