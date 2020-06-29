<?php

include 'header.html';
require 'functions.php';

$xml = new XMLReader();
$xml->open('hosts.xml');

$hosts = array();

// On lance la lecture du XML
while ($xml->read()) {

    // On vérfie que le curseur de lecture se trouve bien sur un noeud et pas du texte
    if ($xml->nodeType == XMLREADER::ELEMENT) {
        if ($xml->localName == 'address' && $xml->getAttribute('addrtype') == 'ipv4') {
            $host = array();
            $host['ipv4'] = $xml->getAttribute('addr');
        }
        if ($xml->localName == 'address' && $xml->getAttribute('addrtype') == 'mac') {
            $host['mac'] = $xml->getAttribute('addr');
        }
        // Si le noeud adress addrtype=='mac' n'existe pas
        else if ($xml->localName == 'address' && $xml->getAttribute('addrtype') != 'mac') {
            $host['mac'] = '-';
        }
        if ($xml->localName == 'osmatch') {
            $host['name'] = $xml->getAttribute('name');
            $host['accuracy'] = $xml->getAttribute('accuracy');
            if (in_array_r($host['mac'], $hosts)){
                $id = searchForId_UsedByHosts($host['mac'], $hosts);
                // Si l'accuracy OS récupéré est > à celle déjà présente dans l'array, on la remplace
                if ($host['accuracy'] > $hosts[$id]['accuracy']) {
                    $hosts[$id]['accuracy'] = $host['accuracy'];
                }
            }
            else $hosts[] = $host;
        }
    }

}

// Variables pour dessiner le chart
$data = arrayDataOS($hosts, 'name');
$countArrayLength = count($data);
?>

<h1 class="title">Machines détectées sur le réseau</h1>

<script type="text/javascript">
// Charge l'API Visualization et les packages nécessaires à Google Charts
google.charts.load('current', {'packages':['corechart']});

// Quand l'API est chargé, on éxecute la fonction de dessin graphique
google.charts.setOnLoadCallback(drawChart);

// Crée et rempli une data table, instancie un bar chart, le rempli de data le dessine
function drawChart() {
    
    var data = new google.visualization.DataTable();
    data.addColumn('string', 'OS');
    data.addColumn('number', 'Nombre');
    data.addColumn({type: 'string', role: 'style'});
    data.addRows([
    <?php
    for($i=0;$i<$countArrayLength;$i++){
        echo "['" . $data[$i]['name'] . "'," . $data[$i]['times'] . ", 'opacity: 0.7'],";
    } 
    ?>
    ]);
    // Options du graphe
    var options = {'title':'Systèmes d\'exploitation',
                    'width':800,
                    'height':400,
                    colors: ['#83C538'],
                    vAxis: {format: '0'},
                    legend:'none'};

    // Dessine le chart avec les options
    var chart = new google.visualization.ColumnChart(document.getElementById('chart_div'));
    chart.draw(data, options);
}
</script>
<div id="chart_div"></div>

<div id="table" class="panel panel-default table-responsive">
    <table class="table table-hover">
        <thead>
            <tr>
            <th class="text-center" scope="col">IP Address</th>
            <th class="text-center" scope="col">MAC Address</th>
            <th class="text-center" scope="col">OS</th>
            <th class="text-center" style="width: 15%" scope="col">Probabilité de l'OS</th>
            </tr>
        </thead>
        <tbody>
<?php
foreach ($hosts as $key=>$value){
    echo '<tr onclick="document.location = \'portsList.php?address=' . $value['ipv4'] . '\';">';
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
include 'footer.html';

?>