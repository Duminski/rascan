<?php
/**
 * Recherche d'une valeur dans un array multidimensionnel.
 * @param string $val Valeur à chercher
 * @param array $array Array dans lequel chercher la valeur
 * @param boolean $strict Si vrai, chaque valeur sera comparée en fonction de son type
 * @return boolean True si la valeur existe dans l'array, false sinon
 */
function in_array_r($val, $array, $strict = false) {
    foreach ($array as $item) {
        if (($strict ? $item === $val : $item == $val) || (is_array($item) && in_array_r($val, $item, $strict))) {
            return true;
        }
    }
    return false;
}

/**
 * Récupère l'index de la valeur que l'on recherche dans un array.
 * @param string $val ID à chercher
 * @param array $array Array dans lequel chercher l'ID
 * @return string Index si la valeur est trouvée dans l'array, null sinon
 */
function searchForId_UsedByHosts($val, $array) {
    foreach ($array as $key => $item) {
        if ($item['ipv4'] === $val) {
            return $key;
        }
   }
   return null;
}

/**
 * Récupère l'index de la valeur que l'on recherche dans un array.
 * @param string $val ID à chercher
 * @param array $array Array dans lequel chercher l'ID
 * @return string Index si la valeur est trouvée dans l'array, null sinon
 */
function searchForId_UsedByOSGraphs($val, $array) {
    foreach ($array as $key => $item) {
        if ($item['name'] === $val) {
            return $key;
        }
   }
   return null;
}

/**
 * Recherche une clé dans un array multidimensionnel.
 * @param array $array Array dans lequel chercher la clé
 * @param string $keySearch Clé à chercher
 * @return boolean True si la clé existe dans l'array, false sinon
 */
function findKey($array, $keySearch) {
    foreach ($array as $key => $item) {
        if ($key == $keySearch || (is_array($item) && findKey($item, $keySearch))) {
            return true;
        } 
    }
    return false;
}

/**
 * Transforme l'array des machines en array ne comprenant que la liste des OS et leur
 * nombre d'apparence.
 * @param array $array Array dans lequel on souhaite extraire des données
 * @param string $key Clé sur laquelle on souhaite extraire des données dans le diagramme
 * @return array Array de liste OS
 */
function arrayDataOS($array, $key) {
    $data = array();
    if (findKey($array, $key)) {
        foreach ($array as $key=>$value){
            if (!(in_array_r($value['name'], $data))) {
                $osmatch = array('name' => $value['name'], 'times' => 1);
                $data[] = $osmatch;
            }
            else {
                $id = searchForId_UsedByOSGraphs($value['name'], $data);
                $data[$id]['times'] = $data[$id]['times'] + 1; 
            }
        }
    }
    return $data;
}

/**
 * Lit le XML pour en extraire un array avec la liste de vulnérabilités.
 * @param string $ipAddress Addresse IP sur laquelle on cherche les vulnérabilités
 * @param string $portID Numéro de port sur lequel on cherche les vulnérabilités
 * @return array Array de liste de vulnérabilités
 */
function readVulnsInXML($ipAddress, $portID){    

    $xml = new XMLReader();
    $xml->open('hosts.xml');
    
    $vulns = array();
    $currAdress = 0;
    $currPortId = 0;
    $nextIsCve = 0;
    $nextIsCvss = 0;
    $oneElem = 0;
    $isFirstFormat = 0;

    while ($xml->read()) {
        // À chaque changement de machines dans l'XML, on change l'adresse IP courante
        if ($xml->localName == 'address' && $xml->getAttribute('addrtype') == 'ipv4') $currAdress = $xml->getAttribute('addr');
        
        // Si le Reader est positionné sur la bonne machine (variable machine == adresse en paramètre)
        if ($currAdress  == $ipAddress) {

            // On cherche le bon port en paramètre URL
            // À chaque changement de ports dans l'XML, on change le port courant
            if ($xml->localName == 'port') $currPortId = $xml->getAttribute('portid');

            if ($currPortId  == $portID) {
                // Si la balise <table key="CVEXXXXX"> existe, alors on récupère le numéro CVE
                if ($xml->nodeType == XMLREADER::ELEMENT && $xml->localName == 'table' && preg_match("/^CVE/", $xml->getAttribute('key'))) {          
                    if (!(isset($vuln))) $vuln = array();              
                    $vuln['IDCve'] = $xml->getAttribute('key');
                    $isFirstFormat = 1;
                }     
                // Sinon c'est que le numéro CVE se trouve dans la balise <elem key="id">CVEXXXXX</elem>
                else if ($xml->nodeType == XMLREADER::ELEMENT && $xml->localName == 'elem' && $xml->getAttribute('key') == 'id') {
                    if (!(isset($vuln))) $vuln = array();  
                    $nextIsCve = 1;
                }
                // On récupère alors ensuite le numéro CVE via la balise <elem> si <elem> contient un attribut key="id"
                if ($nextIsCve == 1 && $xml->nodeType === XMLReader::TEXT) {
                    $vuln['IDCve'] = $xml->value;
                    $nextIsCve = 0;
                }
                // Si on a récupéré le numéro CVE via la balise <table>, on récupère la CVSS de la première balise <elem>, puis on passe à la suite ($oneElem)
                if ($xml->localName == 'elem' && $oneElem == 0 && $isFirstFormat == 1) {
                    $oneElem = 1;
                    $vuln['cvss'] = '-';                     
                    $vulns[] = $vuln;
                    $isFirstFormat = 0;
                }
                // Si on a récupéré le numéro CVE via la balise <elem>, le prochain texte de la balise <elem> sera la CVSS
                else if ($xml->nodeType == XMLREADER::ELEMENT && $xml->localName == 'elem' && $nextIsCve == 0 && $xml->getAttribute('key') == 'cvss') {
                    $nextIsCvss = 1;   
                }               
                // On récupère alors la CVSS si on a récupéré le numéro CVE via la balise <elem>     
                if ($nextIsCvss == 1 && $xml->nodeType === XMLReader::TEXT) {
                    $vuln['cvss'] = $xml->value;                                        
                    $vulns[] = $vuln;
                    $nextIsCvss = 0;
                }
            }
        }
    }
    
    $xml->close();
    return $vulns;

}

?>