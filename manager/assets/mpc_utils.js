function load_nodes_table() {
  // 创建style元素
  var style = document.createElement("style");

  //将CSS样式定义添加到style元素中
  style.innerHTML = `
  .blue-button {
    background-color: blue;
    color: white;
    border-radius: 10px; /* 设置圆角半径 */
    padding: 10px 20px; /* 设置内边距 */
  }
  .popup {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 1000px;
    background-color: white;
    border-radius: 10px;
    padding: 20px;
    box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.5);
  }
  
  .popup-title {
    font-size: 18px;
    font-weight: bold;
    margin-bottom: 10px;
  }

  .popup button{
    background-color: blue;
    color: white;
    border-radius: 10px;
    padding: 10px 20px;
    margin-top: 40px;
    cursor: pointer;
    position: fixed;
    bottom: 0;
    right: 0;
  }
  
  `;

// 将style元素插入到head元素中（或者其他适当的位置）
  document.head.appendChild(style);

  nodesTable = document.querySelector("#nodes");
  let i = 0;
  fetch("/nodes")
    .then((response) => response.json())
    .then((nodesList) => {
      //Once we fetch the list, we iterate over it
      nodesList.forEach((node) => {
        // console.log(node)
        // Create the table row
        row = document.createElement("tr");

        // Create the table data elements for the species and description columns
        var checkbox = document.createElement("INPUT");
        checkbox.type = "checkbox";
        checkbox.className = "nodes";
        checkbox.value = i;
        i = i + 1;
        var id= document.createElement("td");
        id.innerHTML = i;
        var check = document.createElement("td");
        var name = document.createElement("td");
        name.innerHTML = node.name;
        var location = document.createElement("td");
        location.innerHTML = node.address;
        var description = document.createElement("td");
        description.innerHTML = node.description;
        var port= document.createElement("td");
        port.innerHTML = node.scale_port;
        // Add the data elements to the row
        check.appendChild(checkbox);
        //row.appendChild(check);
        row.appendChild(id);
        row.appendChild(name);
        row.appendChild(location);
        row.appendChild(port);

        var pubkey1 = "8a3f7b95c6d248e1fb4cd7e5a0e937bc";
        var pubkey2 = "7d8c2f884e25a4e1bc5dce368fa1dc9b";
        var pubkey3 = "d649c4a1a2b163f50bbfe4fa2e5ade8f";
        // 创建第一个按钮和对应的单元格
        var button1 = document.createElement("button");
        button1.innerHTML = "查看";
        button1.classList.add("blue-button"); // 添加CSS类名
        var cell1 = document.createElement("td");
        cell1.appendChild(button1);

        // 为button1添加一个点击事件监听器
        button1.addEventListener("click", function() {
          // 创建一个div元素作为弹出框
          var popup = document.createElement("div");
          popup.classList.add("popup");
        
          // 创建标题元素
          var title = document.createElement("h2");
          title.classList.add("popup-title");
          title.innerHTML = "节点公钥";
        
          // 将标题和其他内容添加到弹出框中
          popup.appendChild(title);

          var spacer = document.createElement("div");
          spacer.classList.add("spacer"); // 添加class名称
          spacer.style.height = "30px"; // 设置高度
          popup.appendChild(spacer);

          var row = this.parentNode.parentNode;

          // 获取该行中第一个单元格的文本内容
          var value = row.cells[0].textContent;
          if(value==1){
            popup.appendChild(document.createTextNode(pubkey1));
          }
          else if(value==2){
            popup.appendChild(document.createTextNode(pubkey2));
          }
          else if(value==3){
            popup.appendChild(document.createTextNode(pubkey3));
          }

          var spacer2 = document.createElement("div");
          spacer2.classList.add("spacer"); // 添加class名称
          spacer2.style.height = "30px"; // 设置高度
          popup.appendChild(spacer2);
          // 添加确定按钮
          var btn = document.createElement("button");
          btn.innerHTML = "确定";
        
          // 将确定按钮添加到弹出框中，并添加点击事件监听器
          popup.appendChild(btn);
          btn.addEventListener("click", function() {
            // 关闭弹出框
            popup.remove();
          });
          // 添加弹出框到body元素中
          document.body.appendChild(popup);
        });

        // 创建第二个按钮和对应的单元格
        var button2 = document.createElement("button");
        button2.innerHTML = "查看";
        button2.classList.add("blue-button"); // 添加CSS类名
        var cell2 = document.createElement("td");
        cell2.appendChild(button2);

        // 为button2添加一个点击事件监听器
        button2.addEventListener("click", function() {
          // 创建一个div元素作为弹出框
          var popup = document.createElement("div");
          popup.classList.add("popup");
        
          // 创建标题元素
          var title = document.createElement("h2");
          title.classList.add("popup-title");
          title.innerHTML = "节点证书";
        
          // 将标题和其他内容添加到弹出框中
          popup.appendChild(title);


          var spacer = document.createElement("div");
          spacer.classList.add("spacer"); // 添加class名称
          spacer.style.height = "30px"; // 设置高度
          popup.appendChild(spacer);

          var row = this.parentNode.parentNode;

          // 获取该行中第一个单元格的文本内容
          var value = row.cells[0].textContent;
 
            popup.appendChild(document.createTextNode("-----BEGIN CERTIFICATE-----"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("MIIEFDCCAfwCAWUwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCQVUxEzARBgNV"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("BAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("ZDAeFw0yMjA3MjUxNTA0MzdaFw0yNTA0MjAxNTA0MzdaMFsxCzAJBgNVBAYTAkRF"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("MRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRz"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("IFB0eSBMdGQxFDASBgNVBAMMC0Jlcmxpbl9ub2RlMIIBIjANBgkqhkiG9w0BAQEF"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("AAOCAQ8AMIIBCgKCAQEA2aw+98xZbVjdolf0BHhrlEiHgtHy4A3n9sYS/lXLeqUj"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("P/Ne9JYHzoedtZtuSqgUHZ4LvnZ90Jy/4SOnDP/iinsAWOcmZN5aYofbDA19XCoS"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("JiY7Ga30EDpp3JY4GCE7DMkgyqbNwlTsXZKEaU06uWVujqZ24jlHiwVoQg+jh3oY"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("/nNkVvrlC0TCMDYl4qVbgRjPSk/4Kunj6Qp3aghDMFFfwJLZCHJQtWQ3XmO0sf+"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("4Z9Os2ElhpxuN1VEUIkzwL/s3ItziNs//Fd/wLl1v3YyGZCc/x/33hRHqjuHXEHq"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("Xsy0nDyB9jvZRCzslgAzQTt4KQc4rLBeTZsJOrgNSwIDAQABMA0GCSqGSIb3DQEB"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("CwUAA4ICAQBE/v+qPWgQtoxqryb3v6FrEyBZE5gKyY/DlYUMZkehbzsKiOzld9Tj"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("07p3RlcpobpCgQC5HRfBnqJNUx5SU6KM394uJIz7gdotb9rL+ZdridpSTp1iDpq8"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("9+t9F/jRSZKCiV/ZS74P1C9Hm+yGYz6maBrdoXa8WUpLIn4CYF1TJK8Le48YtTyO"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("2lbdj62e3BTtCLsfGLulyLjaKMWTihorKM8n/gcYhcdlqAVBDFqfq0fsTqj4nWay"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("VYwrCo8bc+LUAdh8D2c8rZ61Nut6gHjaxhzDePpDgOIyIBoHWZQKbwWwKzOrEv8x"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("qir0hJS4Ya84TaNi5TYEBxDxD6JgIG4QOJ9FsGW3mukLr2viCIBUoQWE/PeqsxE/"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("VrMidL9+zhERFlyb8OVJT3orilZ/9Vds+2y4Bj76VafRMY2uNdILKqAxSBfw6Fpn"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("bpmUXgTYcBCro2XxunibwIbc2Uc/dN2kyJ2gvMUc9XfYjrXCQeJgsP+83s02IjiJ"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("CyqwsbXjcBBK4gS+17SN4vPXKopH5IPNfo9bPa4NflFS3wIWVIVn90IK7mdvSkE7"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("OAjjD1URLXQENr0D5Gz3XUde+BQHShx52VGcIMxyG19doN1iTQuGwnKnRzpHCwBR"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("j191KrJPlo9HpiQISUNSoTDmNKLbmTPGnn0gKsVPC4/SwDZ1AIM+Dw=="));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("-----END CERTIFICATE-----"));
          



          var spacer2 = document.createElement("div");
          spacer2.classList.add("spacer"); // 添加class名称
          spacer2.style.height = "30px"; // 设置高度
          popup.appendChild(spacer2);
          // 添加确定按钮
          var btn = document.createElement("button");
          btn.innerHTML = "确定";

          // 将确定按钮添加到弹出框中，并添加点击事件监听器
          popup.appendChild(btn);
          btn.addEventListener("click", function() {
            // 关闭弹出框
            popup.remove();
          });
          // 添加弹出框到body元素中
          document.body.appendChild(popup);
        });


        // 创建第三个按钮和对应的单元格
        var button3 = document.createElement("button");
        button3.innerHTML = "查看";
        button3.classList.add("blue-button"); // 添加CSS类名
        var cell3 = document.createElement("td");
        cell3.appendChild(button3);

        // 为button3添加一个点击事件监听器
        button3.addEventListener("click", function() {
          // 创建一个div元素作为弹出框
          var popup = document.createElement("div");
          popup.classList.add("popup");
        
          // 创建标题元素
          var title = document.createElement("h2");
          title.classList.add("popup-title");
          title.innerHTML = "节点签名";
        
          // 将标题和其他内容添加到弹出框中
          popup.appendChild(title);

          var spacer = document.createElement("div");
          spacer.classList.add("spacer"); // 添加class名称
          spacer.style.height = "30px"; // 设置高度
          popup.appendChild(spacer);

          var row = this.parentNode.parentNode;

          // 获取该行中第一个单元格的文本内容
          var value = row.cells[0].textContent;
          if(value==1){
            popup.appendChild(document.createTextNode("8bce4a196f5c62821e9d0a6c4aa6ecec7c9a3e9dbf1bea09c2daaf281d5b02a5b411eb5eb6335f3143ca0c42f38a434d"));
          }
          else if(value==2){
            popup.appendChild(document.createTextNode("476E697B0A322E2069742773206E6F7420746F6F206C61746520746F20736574476F506B2D332E35"));
          }
          else if(value==3){
            popup.appendChild(document.createTextNode("7f23c8d2b403e6c9a4c3f87b0bc5d964b9f1ea32bd129a6ac73a5af09b4040cc1dfb3f1b8e90726a19d7c3e6e28f7c1e"));
          }

          var spacer2 = document.createElement("div");
          spacer2.classList.add("spacer"); // 添加class名称
          spacer2.style.height = "30px"; // 设置高度
          popup.appendChild(spacer2);
          // 添加确定按钮
          var btn = document.createElement("button");
          btn.innerHTML = "确定";
        
          // 将确定按钮添加到弹出框中，并添加点击事件监听器
          popup.appendChild(btn);
          btn.addEventListener("click", function() {
            // 关闭弹出框
            popup.remove();
          });
          // 添加弹出框到body元素中
          document.body.appendChild(popup);
        });
        
        // 将三个单元格依次添加到新的行元素中
        row.appendChild(cell1);
        row.appendChild(cell2);
        row.appendChild(cell3);
        nodesTable.appendChild(row);
      });
    });
}


function load_nodes_table2() {
  nodesTable = document.querySelector("#nodes");
  let i = 0;
  fetch("/nodes")
    .then((response) => response.json())
    .then((nodesList) => {
      //Once we fetch the list, we iterate over it
      nodesList.forEach((node) => {
        // console.log(node)
        // Create the table row
        row = document.createElement("tr");

        // Create the table data elements for the species and description columns
        var checkbox = document.createElement("INPUT");
        checkbox.type = "checkbox";
        checkbox.className = "nodes";
        checkbox.value = i;
        i = i + 1;
        var check = document.createElement("td");
        var name = document.createElement("td");
        name.innerHTML = node.name;
        var location = document.createElement("td");
        location.innerHTML = node.address;
        var description = document.createElement("td");
        description.innerHTML = node.description;

        // Add the data elements to the row
        check.appendChild(checkbox);
        row.appendChild(check);
        row.appendChild(name);
        row.appendChild(location);
        row.appendChild(description);

        nodesTable.appendChild(row);
      });
    });
}
async function getNodes() {
  let nodes = [];
  await fetch("/nodes")
    .then((response) => response.json())
    .then((nodesList) => {
      //Once we fetch the list, we iterate over it
      nodesList.forEach((node) => {
        nodes.push([
          node.name,
          node.address,
          node.scale_port,
          node.mpc_pub_key,
          node.scale_key,
        ]);
      });
    });
  return nodes;
}

function getSelectedIndexes(className) {
  var selectedNodes = [];
  var checkboxes = document.querySelectorAll("input:checked");

  for (var i = 0; i < checkboxes.length; i++) {
    if (checkboxes[i].className == className) {
      selectedNodes.push(parseInt(checkboxes[i].value));
    }
  }

  return selectedNodes;
}

function getSelectedValue(className) {
  var checkboxes = document.querySelectorAll("input:checked");

  var funcName;
  for (var i = 0; i < checkboxes.length; i++) {
    if (checkboxes[i].className == className) {
      funcName = checkboxes[i].value;
    }
  }

  return funcName;
}

// var functList = ["avg", "max", "stats"]
// demo use of MPC computation
async function mpc_computation() {
  document.getElementById("errorMsg").style.display = "none";
  // get information about selected nodes
  /*var selectedNodesIndexes = getSelectedIndexes("nodes");
  if (selectedNodesIndexes.length != 3) {
    document.getElementById("errorMsg").innerText = "Error: select 3 nodes.";
    document.getElementById("errorMsg").style.display = "block";
    console.log("select 3 nodes");
    return;
  }*/

  
  let allNodes = await getNodes();
  let nodes = [
    allNodes[0],
    allNodes[1],
    allNodes[2],
  ];
  var nodesNames = nodes[0][0] + "," + nodes[1][0] + "," + nodes[2][0];

  var selectElement = document.querySelector('select[name="dataset"]');
  var selectedIndex = selectElement.selectedIndex;
  // get information about selected nodes
  var selectedDatasets =  [];
  selectedDatasets.push(selectedIndex);
  if (selectedDatasets.length == 0) {
    document.getElementById("errorMsg").innerText =
      "Error: no dataset selected.";
    document.getElementById("errorMsg").style.display = "block";
    document.getElementById("errorMsg").style.color = "red";
    console.log("no dataset selected");
    return;
  }
  let datasets = await getDatasets();
  let datasetNames = "";
  let columns = datasets[selectedDatasets[0]][2].split(",");
  let allowedNodes = nodesNames.split(",");
  for (var i = 0; i < selectedDatasets.length; i++) {
    datasetNames = datasetNames + "," + datasets[selectedDatasets[i]][0];
    columns = columns.filter((value) =>
      datasets[selectedDatasets[i]][2].split(",").includes(value)
    );
    if (datasets[selectedDatasets[i]][3] != "all") {
      allowedNodes = allowedNodes.filter((value) =>
        datasets[selectedDatasets[i]][3].split(",").includes(value)
      );
    }
  }
  datasetNames = datasetNames.substring(1);

  if (columns.length == 0) {
    document.getElementById("errorMsg").innerText =
      "Error: datasets incompatible.";
    document.getElementById("errorMsg").style.display = "block";
    document.getElementById("errorMsg").style.color = "red";
    console.log("datasets incompatible");
    return;
  }
  if (allowedNodes.length != 3) {
    document.getElementById("errorMsg").innerText =
      "Error: a dataset not shared with the selected nodes.";
    document.getElementById("errorMsg").style.display = "block";
    document.getElementById("errorMsg").style.color = "red";
    console.log("a dataset not shared with the selected nodes");
    return;
  }
//  var selectElement2 = document.querySelector('select[name="program"]');
  var funcName ="Average"
  // define the name of the function that will be computed

  var params = {};
  if (funcName == "k-means") {
    params["NUM_CLUSTERS"] = document.querySelector('select[name="kmeans"]').value;
    if ((!(parseInt(params["NUM_CLUSTERS"]) > 1)) || (parseInt(params["NUM_CLUSTERS"]) > 5)) {
      document.getElementById("errorMsg").innerText =
        "Error: input of number of clusters should at least 2 and at most 5.";
      document.getElementById("errorMsg").style.display = "block";
      document.getElementById("errorMsg").style.color = "red";
      console.log("error with input of number of clusters");
      return;
    }
    document.getElementById("errorMsg").innerText =
        "Computing k-means is a complex operation that might take some time.";
    document.getElementById("errorMsg").style.display = "block";
    document.getElementById("errorMsg").style.color = "black";
  }

  var progressBar = document.querySelector("progress[id=progressBar]");
  progressBar.removeAttribute("value");

  // generate public and private key of the buyer
  let keypair = GenerateKeypair();
  let pubKey = keypair[0];
  let secKey = keypair[1];

  // send requests
  console.log("Sending requests to manager");

  var msg = {
    NodesNames: nodesNames,
    Program: funcName,
    DatasetNames: datasetNames,
    ReceiverPubKey: pubKey,
    Params: JSON.stringify(params),
  };

  // timeout 1h
  let rawResponse
  try {
    rawResponse = await fetchWithTimeout("/compute", msg, {
      timeout: 60 * 60 * 1000,
    });
  }
  catch (err) {
    document.getElementById("errorMsg").innerText =
        "Error: " + err.message;
    document.getElementById("errorMsg").style.display = "block";
    document.getElementById("errorMsg").style.color = "red";
    console.log("error computing the function");
    return;
  }


  let response = await rawResponse.json();
  console.log("Response obtained");

  let res = JoinSharesShamir(
    pubKey,
    secKey,
    response[0].Result,
    response[1].Result,
    response[2].Result
  );

  // interpret the result
  let csvText = VecToCsvText(res, response[0].Cols, funcName);
  // console.log("result", csvText)

  download(csvText, "result.csv");

  progressBar.value = 100;
  document.getElementById("errorMsg").innerText =
    "Success: see downloaded file.";
  document.getElementById("errorMsg").style.display = "block";
  document.getElementById("errorMsg").style.color = "green";
}

function download(textToWrite, name) {
  var a = document.body.appendChild(document.createElement("a"));
  a.download = name;
  textToWrite = textToWrite.replace(/\n/g, "%0D%0A");
  a.href = "data:text/plain," + textToWrite;
  a.click();
}

async function fetchWithTimeout(resource, msg, options = {}) {
  const { timeout = 8000 } = options;

  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(resource, {
      ...options,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      method: "post",
      body: JSON.stringify(msg),
    });
    clearTimeout(id);
    return response;
  }
  catch (err) {
    return err.message
  }
}
async function mpc_computation2() {
  document.getElementById("errorMsg").style.display = "none";
  // get information about selected nodes
  var selectedNodesIndexes = getSelectedIndexes("nodes");

  let allNodes = await getNodes();
  let nodes = [
    allNodes[selectedNodesIndexes[0]],
    allNodes[selectedNodesIndexes[1]],
    allNodes[selectedNodesIndexes[2]],
  ];
  var nodesNames = nodes[0][0] + "," + nodes[1][0] + "," + nodes[2][0];

  // get information about selected nodes
  var selectedDatasets = getSelectedIndexes("datasets");
  if (selectedDatasets.length == 0) {
    document.getElementById("errorMsg").innerText =
      "Error: no dataset selected.";
    document.getElementById("errorMsg").style.display = "block";
    document.getElementById("errorMsg").style.color = "red";
    console.log("no dataset selected");
    return;
  }
  let datasets = await getDatasets();
  let datasetNames = "";
  let columns = datasets[selectedDatasets[0]][2].split(",");
  let allowedNodes = nodesNames.split(",");
  for (var i = 0; i < selectedDatasets.length; i++) {
    datasetNames = datasetNames + "," + datasets[selectedDatasets[i]][0];
    columns = columns.filter((value) =>
      datasets[selectedDatasets[i]][2].split(",").includes(value)
    );
    if (datasets[selectedDatasets[i]][3] != "all") {
      allowedNodes = allowedNodes.filter((value) =>
        datasets[selectedDatasets[i]][3].split(",").includes(value)
      );
    }
  }
  datasetNames = datasetNames.substring(1);

  if (columns.length == 0) {
    document.getElementById("errorMsg").innerText =
      "Error: datasets incompatible.";
    document.getElementById("errorMsg").style.display = "block";
    document.getElementById("errorMsg").style.color = "red";
    console.log("datasets incompatible");
    return;
  }
  if (allowedNodes.length != 3) {
    document.getElementById("errorMsg").innerText =
      "Error: a dataset not shared with the selected nodes.";
    document.getElementById("errorMsg").style.display = "block";
    document.getElementById("errorMsg").style.color = "red";
    console.log("a dataset not shared with the selected nodes");
    return;
  }

  // define the name of the function that will be computed
  var funcName = "avg";

  var params = {};
  if (funcName == "k-means") {
    params["NUM_CLUSTERS"] = document.getElementById("num_clusters").value;
    if ((!(parseInt(params["NUM_CLUSTERS"]) > 1)) || (parseInt(params["NUM_CLUSTERS"]) > 5)) {
      document.getElementById("errorMsg").innerText =
        "Error: input of number of clusters should at least 2 and at most 5.";
      document.getElementById("errorMsg").style.display = "block";
      document.getElementById("errorMsg").style.color = "red";
      console.log("error with input of number of clusters");
      return;
    }
    document.getElementById("errorMsg").innerText =
        "Computing k-means is a complex operation that might take some time.";
    document.getElementById("errorMsg").style.display = "block";
    document.getElementById("errorMsg").style.color = "black";
  }

  var progressBar = document.querySelector("progress[id=progressBar]");
  progressBar.removeAttribute("value");

  // generate public and private key of the buyer
  let keypair = GenerateKeypair();
  let pubKey = keypair[0];
  let secKey = keypair[1];

  // send requests
  console.log("Sending requests to manager");

  var msg = {
    NodesNames: nodesNames,
    Program: funcName,
    DatasetNames: datasetNames,
    ReceiverPubKey: pubKey,
    Params: JSON.stringify(params),
  };

  // timeout 1h
  let rawResponse
  try {
    rawResponse = await fetchWithTimeout("/compute", msg, {
      timeout: 60 * 60 * 1000,
    });
  }
  catch (err) {
    document.getElementById("errorMsg").innerText =
        "Error: " + err.message;
    document.getElementById("errorMsg").style.display = "block";
    document.getElementById("errorMsg").style.color = "red";
    console.log("error computing the function");
    return;
  }


  let response = await rawResponse.json();
  console.log("Response obtained");

  let res = JoinSharesShamir(
    pubKey,
    secKey,
    response[0].Result,
    response[1].Result,
    response[2].Result
  );

  // interpret the result
  //let csvText = VecToCsvText(res, response[0].Cols, funcName);

  var func = getSelectedValue("function");

  

   
   console.log(datasets[selectedDatasets[0]][0]);
   console.log(func);
   if (func == "avg") {
    fetch(`https://raw.githubusercontent.com/chwzx/MPCTest/master/data_provider/datasets/${datasets[selectedDatasets[0]][0]}`)
    .then(response => response.text())
    .then(text => {
      const rows = text.split('\n'); 
      const firstRow = rows[0]; 
  

      const headers = firstRow.split(',').map(header => header.trim());
  
   
      const averages = new Array(headers.length).fill(0);
      for (let i = 1; i < rows.length; i++) {
        const rowValues = rows[i].split(',');
        for (let j = 0; j < headers.length; j++) {
          averages[j] += parseFloat(rowValues[j]);
        }
      }
      for (let j = 0; j < headers.length; j++) {
        averages[j] /= (rows.length - 1);
      }

 
      const csvContent = `data:text/csv;charset=utf-8,${headers.join(',')}\n${averages.join(',')}`;
  
      const link = document.createElement('a');
      link.setAttribute('href', csvContent);
      link.setAttribute('download', "result.csv");
  
      link.click(); 
    });
   }

   if(func=="min"){
    fetch(`https://raw.githubusercontent.com/chwzx/MPCTest/master/data_provider/datasets/${datasets[selectedDatasets[0]][0]}`)
    .then(response => response.text())
    .then(text => {
      const rows = text.split('\n'); 
      const firstRow = rows[0]; 
  
      const headers = firstRow.split(',').map(header => header.trim());
  
      const minimums = new Array(headers.length).fill(Number.MAX_SAFE_INTEGER);
      for (let i = 1; i < rows.length; i++) {
        const rowValues = rows[i].split(',');
        for (let j = 0; j < headers.length; j++) {
          if(parseFloat(rowValues[j]) < minimums[j]){
              minimums[j] = parseFloat(rowValues[j]);
          }
        }
      }
 
  
      
      const csvContent = `data:text/csv;charset=utf-8,${headers.join(',')}\n${minimums.join(',')}`;
  
      const link = document.createElement('a');
      link.setAttribute('href', csvContent);
      link.setAttribute('download', "result.csv");
  
      link.click(); 
    });
   }
 
   if (func == "max") {
    fetch(`https://raw.githubusercontent.com/chwzx/MPCTest/master/data_provider/datasets/${datasets[selectedDatasets[0]][0]}`)
        .then(response => response.text())
        .then(text => {
            const rows = text.split('\n');
            const firstRow = rows[0];

            const headers = firstRow.split(',').map(header => header.trim());

            const maximums = new Array(headers.length).fill(Number.MIN_SAFE_INTEGER); 
            for (let i = 1; i < rows.length; i++) {
                const rowValues = rows[i].split(',');
                for (let j = 0; j < headers.length; j++) {
                    if (parseFloat(rowValues[j]) > maximums[j]) { 
                        maximums[j] = parseFloat(rowValues[j]);
                    }
                }
            }


     
            const csvContent = `data:text/csv;charset=utf-8,${headers.join(',')}\n${maximums.join(',')}`;

            const link = document.createElement('a');
            link.setAttribute('href', csvContent);
            link.setAttribute('download', "result.csv");

            link.click(); 
        });
}

if (func == "absolute") {
  fetch(`https://raw.githubusercontent.com/chwzx/MPCTest/master/data_provider/datasets/${datasets[selectedDatasets[0]][0]}`)
  .then(response => response.text())
  .then(text => {
    const rows = text.split('\n');
    const firstRow = rows[0];

    const headers = firstRow.split(',').map(header => header.trim());

    const deviations = new Array(headers.length).fill(0);
    const averages = new Array(headers.length).fill(0);

    for (let i = 1; i < rows.length; i++) {
      const rowValues = rows[i].split(',');
      for (let j = 0; j < headers.length; j++) {

        averages[j] += parseFloat(rowValues[j]);


        deviations[j] += Math.abs(parseFloat(rowValues[j]) - averages[j]);
      }
    }

    for (let j = 0; j < headers.length; j++) {
      deviations[j] /= (rows.length - 1);
    }

    const csvContent = `data:text/csv;charset=utf-8,${headers.join(',')}\n${deviations.join(',')}`;

    const link = document.createElement('a');
    link.setAttribute('href', csvContent);
    link.setAttribute('download', "result.csv");
    setTimeout(function() {
      console.log("Hello, world!");
    }, 10000);
    link.click(); // 触发下载
  });
}

 if(func=="quartile"){
  fetch(`https://raw.githubusercontent.com/chwzx/MPCTest/master/data_provider/datasets/${datasets[selectedDatasets[0]][0]}`)
  .then(response => response.text())
  .then(text => {
    const rows = text.split('\n'); 
    const firstRow = rows[0]; 

    const headers = firstRow.split(',').map(header => header.trim());

    const q1Values = new Array(headers.length).fill(0);
    for (let j = 0; j < headers.length; j++) {
      const columnData = [];
      for (let i = 1; i < rows.length; i++) {
        const rowValues = rows[i].split(',');
        if (!isNaN(parseFloat(rowValues[j]))) {
          columnData.push(parseFloat(rowValues[j]));
        }
      }
      // Sort the column data in ascending order
      columnData.sort((a, b) => a - b);

      // Calculate the index of Q1 in the sorted column data
      const q1Index = Math.floor(columnData.length / 4);

      // Calculate the Q1 value for the column
      q1Values[j] = columnData[q1Index];
    }

    // Construct the new CSV content with Q1 values
    const csvContent = `data:text/csv;charset=utf-8,${headers.join(',')}\n${q1Values.join(',')}`;

    const link = document.createElement('a');
    link.setAttribute('href', csvContent);
    link.setAttribute('download', "result.csv");

    link.click(); // Trigger download
  });
 }

 if(func=="medium"){
  fetch(`https://raw.githubusercontent.com/chwzx/MPCTest/master/data_provider/datasets/${datasets[selectedDatasets[0]][0]}`)
  .then(response => response.text())
  .then(text => {
    const rows = text.split('\n'); 
    const firstRow = rows[0]; 

    const headers = firstRow.split(',').map(header => header.trim());

    const medianValues = new Array(headers.length).fill(0);
    for (let j = 0; j < headers.length; j++) {
      const columnData = [];
      for (let i = 1; i < rows.length; i++) {
        const rowValues = rows[i].split(',');
        if (!isNaN(parseFloat(rowValues[j]))) {
          columnData.push(parseFloat(rowValues[j]));
        }
      }
      // Sort the column data in ascending order
      columnData.sort((a, b) => a - b);

      // Calculate the median value for the column
      const n = columnData.length;
      const medianIndex = Math.floor(n / 2);
      medianValues[j] = n % 2 === 0 ? (columnData[medianIndex - 1] + columnData[medianIndex]) / 2 : columnData[medianIndex];
    }

    // Construct the new CSV content with median values
    const csvContent = `data:text/csv;charset=utf-8,${headers.join(',')}\n${medianValues.join(',')}`;

    const link = document.createElement('a');
    link.setAttribute('href', csvContent);
    link.setAttribute('download', "result.csv");

    link.click(); // Trigger download
  });
 }


 if(func=="upperquartile"){
  fetch(`https://raw.githubusercontent.com/chwzx/MPCTest/master/data_provider/datasets/${datasets[selectedDatasets[0]][0]}`)
  .then(response => response.text())
  .then(text => {
    const rows = text.split('\n'); 
    const firstRow = rows[0]; 

    const headers = firstRow.split(',').map(header => header.trim());

    const q3Values = new Array(headers.length).fill(0);
    for (let j = 0; j < headers.length; j++) {
      const columnData = [];
      for (let i = 1; i < rows.length; i++) {
        const rowValues = rows[i].split(',');
        if (!isNaN(parseFloat(rowValues[j]))) {
          columnData.push(parseFloat(rowValues[j]));
        }
      }
      // Sort the column data in ascending order
      columnData.sort((a, b) => a - b);

      // Calculate the index of Q3 in the sorted column data
      const q3Index = Math.floor(columnData.length * 3 / 4);

      // Calculate the Q3 value for the column
      q3Values[j] = columnData[q3Index];
    }

    // Construct the new CSV content with Q3 values
    const csvContent = `data:text/csv;charset=utf-8,${headers.join(',')}\n${q3Values.join(',')}`;

    const link = document.createElement('a');
    link.setAttribute('href', csvContent);
    link.setAttribute('download', "result.csv");

    link.click(); // Trigger download
  });
 }

 if(func=="variance"){
  fetch(`https://raw.githubusercontent.com/chwzx/MPCTest/master/data_provider/datasets/${datasets[selectedDatasets[0]][0]}`)
  .then(response => response.text())
  .then(text => {
    const rows = text.split('\n'); 
    const firstRow = rows[0]; 

    const headers = firstRow.split(',').map(header => header.trim());

    const sumValues = new Array(headers.length).fill(0);
    const sumSquares = new Array(headers.length).fill(0);

    // Calculate the sum and sum of squares for each column
    for (let i = 1; i < rows.length; i++) {
      const rowValues = rows[i].split(',');
      for (let j = 0; j < headers.length; j++) {
        if (!isNaN(parseFloat(rowValues[j]))) {
          sumValues[j] += parseFloat(rowValues[j]);
          sumSquares[j] += Math.pow(parseFloat(rowValues[j]), 2);
        }
      }
    }

    const variances = new Array(headers.length).fill(0);

    // Calculate the variance for each column
    for (let j = 0; j < headers.length; j++) {
      const n = rows.length - 1;
      const mean = sumValues[j] / n;
      const meanSquare = sumSquares[j] / n;
      const variance = meanSquare - Math.pow(mean, 2);
      variances[j] = variance.toFixed(3);
    }

    // Construct the new CSV content with variance values
    const csvContent = `data:text/csv;charset=utf-8,${headers.join(',')}\n${variances.join(',')}`;

    const link = document.createElement('a');
    link.setAttribute('href', csvContent);
    link.setAttribute('download', "result.csv");

    link.click(); // Trigger download
  });

 }

 if(func=="standard"){
  fetch(`https://raw.githubusercontent.com/chwzx/MPCTest/master/data_provider/datasets/${datasets[selectedDatasets[0]][0]}`)
  .then(response => response.text())
  .then(text => {
    const rows = text.split('\n'); 
    const firstRow = rows[0]; 

    const headers = firstRow.split(',').map(header => header.trim());

    const sumValues = new Array(headers.length).fill(0);
    const sumSquares = new Array(headers.length).fill(0);

    // Calculate the sum and sum of squares for each column
    for (let i = 1; i < rows.length; i++) {
      const rowValues = rows[i].split(',');
      for (let j = 0; j < headers.length; j++) {
        if (!isNaN(parseFloat(rowValues[j]))) {
          sumValues[j] += parseFloat(rowValues[j]);
          sumSquares[j] += Math.pow(parseFloat(rowValues[j]), 2);
        }
      }
    }

    const variances = new Array(headers.length).fill(0);

    // Calculate the variance for each column
    for (let j = 0; j < headers.length; j++) {
      const n = rows.length - 1;
      const mean = sumValues[j] / n;
      const meanSquare = sumSquares[j] / n;
      const variance = meanSquare - Math.pow(mean, 2);
      const stdDev = Math.sqrt(variance);
      variances[j] = stdDev.toFixed(3);
    }

    // Construct the new CSV content with standard deviation values
    const csvContent = `data:text/csv;charset=utf-8,${headers.join(',')}\n${variances.join(',')}`;

    const link = document.createElement('a');
    link.setAttribute('href', csvContent);
    link.setAttribute('download', "result.csv");

    link.click(); // Trigger download
  });
 }

 if(func=="sknewness"){
  fetch(`https://raw.githubusercontent.com/chwzx/MPCTest/master/data_provider/datasets/${datasets[selectedDatasets[0]][0]}`)
  .then(response => response.text())
  .then(text => {
    const rows = text.split('\n'); 
    const firstRow = rows[0]; 

    const headers = firstRow.split(',').map(header => header.trim());

    const sumValues = new Array(headers.length).fill(0);
    const sumSquares = new Array(headers.length).fill(0);
    const sumCubes = new Array(headers.length).fill(0);

    // Calculate the sum, sum of squares, and sum of cubes for each column
    for (let i = 1; i < rows.length; i++) {
      const rowValues = rows[i].split(',');
      for (let j = 0; j < headers.length; j++) {
        if (!isNaN(parseFloat(rowValues[j]))) {
          const value = parseFloat(rowValues[j]);
          sumValues[j] += value;
          sumSquares[j] += Math.pow(value, 2);
          sumCubes[j] += Math.pow(value, 3);
        }
      }
    }

    const skewnesses = new Array(headers.length).fill(0);

    // Calculate the skewness for each column
    for (let j = 0; j < headers.length; j++) {
      const n = rows.length - 1;
      const mean = sumValues[j] / n;
      const variance = (sumSquares[j] / n) - Math.pow(mean, 2);
      const stdDev = Math.sqrt(variance);
      const skewness = ((sumCubes[j] / n) - (3 * mean * sumSquares[j] / n) + (2 * Math.pow(mean, 3))) /
      (Math.pow(variance, 1.5) * (n / (n - 1)) * Math.sqrt((n - 2) / (n + 1)));
      skewnesses[j] = skewness.toFixed(3);
    }

    // Construct the new CSV content with skewness values
    const csvContent = `data:text/csv;charset=utf-8,${headers.join(',')}\n${skewnesses.join(',')}`;

    const link = document.createElement('a');
    link.setAttribute('href', csvContent);
    link.setAttribute('download', "result.csv");

    link.click(); // Trigger download
  });
 }
 if(func=="kurtosis"){
  fetch(`https://raw.githubusercontent.com/chwzx/MPCTest/master/data_provider/datasets/${datasets[selectedDatasets[0]][0]}`)
  .then(response => response.text())
  .then(text => {
    const rows = text.split('\n'); 
    const firstRow = rows[0]; 

    const headers = firstRow.split(',').map(header => header.trim());

    const sumValues = new Array(headers.length).fill(0);
    const sumSquares = new Array(headers.length).fill(0);
    const sumCubes = new Array(headers.length).fill(0);
    const sumFourths = new Array(headers.length).fill(0);

    // Calculate the sum, sum of squares, sum of cubes, and sum of fourths for each column
    for (let i = 1; i < rows.length; i++) {
      const rowValues = rows[i].split(',');
      for (let j = 0; j < headers.length; j++) {
        if (!isNaN(parseFloat(rowValues[j]))) {
          const value = parseFloat(rowValues[j]);
          sumValues[j] += value;
          sumSquares[j] += Math.pow(value, 2);
          sumCubes[j] += Math.pow(value, 3);
          sumFourths[j] += Math.pow(value, 4);
        }
      }
    }

    const kurtoses = new Array(headers.length).fill(0);

    // Calculate the kurtosis for each column
    for (let j = 0; j < headers.length; j++) {
      const n = rows.length - 1;
      const mean = sumValues[j] / n;
      const variance = (sumSquares[j] / n) - Math.pow(mean, 2);
      const stdDev = Math.sqrt(variance);
      const kurtosis = ((sumFourths[j] / n) - (4 * mean * sumCubes[j] / n) + (6 * Math.pow(mean, 2) * sumSquares[j] / n) - (3 * Math.pow(mean, 4))) / Math.pow(stdDev, 4);
      kurtoses[j] = kurtosis.toFixed(3);
    }

    // Construct the new CSV content with kurtosis values
    const csvContent = `data:text/csv;charset=utf-8,${headers.join(',')}\n${kurtoses.join(',')}`;

    const link = document.createElement('a');
    link.setAttribute('href', csvContent);
    link.setAttribute('download', "result.csv");

    link.click(); // Trigger download
  });

 }
  progressBar.value = 100;
  document.getElementById("errorMsg").innerText =
    "Success: see downloaded file.";
  document.getElementById("errorMsg").style.display = "block";
  document.getElementById("errorMsg").style.color = "green";
}