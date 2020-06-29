<?php

// Recherche d'une valeur dans un array multidim. (array dans un array)
function in_array_r($needle, $haystack, $strict = false) {
    foreach ($haystack as $item) {
        if (($strict ? $item === $needle : $item == $needle) || (is_array($item) && in_array_r($needle, $item, $strict))) {
            return true;
        }
    }

    return false;
}

// Récupère l'index de la valeur que l'on recherche dans un array
function searchForId_UsedByHosts($id, $array) {
    foreach ($array as $key => $val) {
        if ($val['mac'] === $id) {
            return $key;
        }
   }
   return null;
}

// Récupère l'index de la valeur que l'on recherche dans un array
function searchForId_UsedByOSGraphs($id, $array) {
    foreach ($array as $key => $val) {
        if ($val['name'] === $id) {
            return $key;
        }
   }
   return null;
}

// Recherche d'une clé dans un array multidim.
function findKey($array, $keySearch)
{
    foreach ($array as $key => $item) {
        if ($key == $keySearch) {
            return true;
        } elseif (is_array($item) && findKey($item, $keySearch)) {
            return true;
        }
    }
    return false;
}

// Convertit des données en JSON pour le graphique OS
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
                if ($xml->nodeType == XMLREADER::ELEMENT && $xml->localName == 'table' && preg_match("/^CVE/", $xml->getAttribute('key'))) {          
                    if (!(isset($vuln))) $vuln = array();              
                    $vuln['IDCve'] = $xml->getAttribute('key');
                    $isFirstFormat = 1;
                }         
                else if ($xml->nodeType == XMLREADER::ELEMENT && $xml->localName == 'elem' && $xml->getAttribute('key') == 'id') {
                    if (!(isset($vuln))) $vuln = array();  
                    $nextIsCve = 1;
                }
                if ($nextIsCve == 1 && $xml->nodeType === XMLReader::TEXT) {
                    $vuln['IDCve'] = $xml->value;
                    $nextIsCve = 0;
                }
                if (($xml->localName == 'elem' && $oneElem == 0 && $isFirstFormat == 1)) {
                    $oneElem = 1;
                    $vuln['cvss'] = '-';                     
                    $vulns[] = $vuln;
                    $isFirstFormat = 0;
                }
                else if ($xml->nodeType == XMLREADER::ELEMENT && $xml->localName == 'elem' && $nextIsCve == 0 && $xml->getAttribute('key') == 'cvss') {
                    $nextIsCvss = 1;   
                }                    
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