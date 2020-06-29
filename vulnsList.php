<?php

include 'header.html';
require 'functions.php';

if (isset($_GET['portID']) && !empty($_GET['portID']) && trim($_GET['portID'] != '') &&
    isset($_GET['service']) && !empty($_GET['service']) && trim($_GET['service'] != '') &&
    isset($_GET['address']) && !empty($_GET['address']) && trim($_GET['address'] != '')) {
    $portID = htmlspecialchars(htmlentities($_GET['portID']));
    $service = htmlspecialchars(htmlentities($_GET['service']));
    $ipAddress = htmlspecialchars(htmlentities($_GET['address']));

    $vulns = array();
    $vulns = readVulnsInXML($ipAddress, $portID);
    
    ?>

<h1 class="title">Vulnérabilités du service <?php echo $service; ?></h1>

<div class="arrowFirst">
    <a href="portsList.php?address=<?php echo $ipAddress ?>"><img src="left-arrow.png" alt="left-arrow">Liste des ports</a>
</div>

<div class="arrow">
    <a href="index.php"><img src="left-arrow.png" alt="left-arrow">Liste des machines</a>
</div>

<div id="table" class="panel panel-default table-responsive">
    <table class="table table-hover">
        <thead>
            <tr>
            <th class="text-center" scope="col">ID CVE</th>
            <th class="text-center" scope="col">Gravité</th>
            </tr>
        </thead>
        <tbody>
<?php
foreach ($vulns as $key=>$value){
    echo '<tr>';
    foreach ($value as $valueT){
        echo '<td>' . $valueT . '</td>';
    }
    echo '</tr>';
}
?>
        </tbody>
    </table>
</div>

<?php
}
else echo '<p>No value given as a parameter</p>';

include 'footer.html';

?>