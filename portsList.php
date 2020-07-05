<?php

require 'header.html';
require 'functions.php';

if (isset($_GET['address']) && !empty($_GET['address']) && trim($_GET['address'] != '')) {
    $ipAddress = htmlspecialchars(htmlentities($_GET['address']));

    $xml = new XMLReader();
    $xml->open('hosts.xml');

    $vulns = array();
    $psvs = array();
    $currAdress = 0;

    while ($xml->read()) {

        // On vérfie que le curseur de lecture se trouve bien sur un noeud et pas du texte
        if ($xml->nodeType == XMLREADER::ELEMENT) {

            // À chaque changement de machines dans l'XML, on change l'adresse IP courante
            if ($xml->localName == 'address' && $xml->getAttribute('addrtype') == 'ipv4') $currAdress = $xml->getAttribute('addr');
            
            // Si le Reader est positionné sur la bonne machine (variable machine == adresse en paramètre)
            if ($currAdress  == $ipAddress) {
                if ($xml->localName == 'port') {
                    $psv = array();
                    $psv['protocol'] = $xml->getAttribute('protocol');
                    $psv['portNb'] = $xml->getAttribute('portid');
                }
                if ($xml->localName == 'state') {
                    if ($xml->getAttribute('state') == 'open') $psv['state'] = 'Ouvert';
                    else $psv['state'] = 'Fermé';
                }
                if ($xml->localName == 'service') {
                    // Si le service est renseigné 'unknown', on le remplace par '-'
                    if ($xml->getAttribute('name') == 'unknown') $psv['serviceName'] = '-';
                    else $psv['serviceName'] = $xml->getAttribute('name');
                    if ($xml->getAttribute('version') != NULL) $psv['serviceVersion'] = $xml->getAttribute('version');
                    // S'il n'y pas d'attribut version, on remplace la version pas '-'
                    else $psv['serviceVersion'] = '-';
                    // On regarde si des vulnérabilités sont existantes pour ce PSV
                    $vulns = readVulnsInXML($ipAddress, $psv['portNb']);
                    if (empty($vulns)) $psv['vulnerable'] = 'Non';
                    else $psv['vulnerable'] = 'Oui';
                    $psvs[] = $psv;
                }
            }
        }
    }

    ?>

<h1 class="title">Ports, services et versions de l'adresse <?php echo $ipAddress; ?></h1>

<div class="arrow">
    <a href="index.php"><img src="left-arrow.png" alt="left-arrow">Liste des machines</a>
</div>

<div id="table" class="panel panel-default table-responsive">
    <table class="table table-hover">
        <thead>
            <tr>
            <th class="text-center" scope="col">Protocole</th>
            <th class="text-center" scope="col">Numéro du port</th>
            <th class="text-center" scope="col">État du port</th>
            <th class="text-center" scope="col">Nom du service</th>
            <th class="text-center" scope="col">Version du service</th>
            <th class="text-center" scope="col">Vulnérable ?</th>
            </tr>
        </thead>
        <tbody>
<?php
foreach ($psvs as $key=>$value){
    echo '<tr onclick="document.location = \'vulnsList.php?portID=' . $value['portNb'] . '&address=' . $ipAddress . '&service=' . $value['serviceName'] . '\';">';
    foreach ($value as $valueT){
        echo '<td class="clickable">' . $valueT . '</td>';
    }
    echo '</tr>';
}
?>
        </tbody>
    </table>
</div>

<?php
$xml->close();
}
else echo '<p>No value given as a parameter</p>';

include 'footer.html';

?>