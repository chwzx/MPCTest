function load_datasets_table() {
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
      width: 1200px;
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
  datasetsTable = document.querySelector("#datasets");

  // datasetsTable.innerHTML = "";
  // row = document.createElement("tr");
  // var th = document.createElement("th");
  // th.innerHTML = "";
  // row.appendChild(th);
  // var th2 = document.createElement("th");
  // th2.innerHTML = "Dataset";
  // row.appendChild(th2);
  // var th3 = document.createElement("th");
  // th3.innerHTML = "Data entries (size)";
  // row.appendChild(th3);
  // var th4 = document.createElement("th");
  // th4.innerHTML = "Shared with";
  // row.appendChild(th4);
  // datasetsTable.appendChild(row);

  let i = 0;
  // fetch("/datasets")

  fetch("/datasets")
    .then((response) => response.json())
    .then((datasetsList) => {
      //Once we fetch the list, we iterate over it
      datasetsList.forEach((dataset) => {
        // console.log(dataset)
        // Create the table row
        row = document.createElement("tr");

        // Create the table data elements for the species and description columns
        //var checkbox = document.createElement("INPUT");
        //checkbox.type = "checkbox";
        //checkbox.className = "datasets";
        //checkbox.value = i;
        i = i + 1;
        //var check = document.createElement("td");
        var id = document.createElement("td");
        id.innerHTML = i;
        var name = document.createElement("td");
        name.innerHTML = dataset.name;
        var dataprovider = document.createElement("td");
        dataprovider.innerHTML = "data_provider_test";
        var size = document.createElement("td");
        size.innerHTML = dataset.size;
        const now = new Date();
        const year = now.getFullYear();
        const month = now.getMonth() + 1; // 加一因为月份从0开始计数
        const day = now.getDate();
        const hours = now.getHours();
        const minutes = now.getMinutes();
        const seconds = now.getSeconds();
        const formattedTime = `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
        var time = document.createElement("td");
        time.innerHTML = formattedTime;
        // var cols = document.createElement("td");
        // cols.innerHTML = dataset.cols;
        //var shared_nodes = document.createElement("td");
        //shared_nodes.innerHTML = dataset.shared_with;

        // Add the data elements to the row
        //check.appendChild(checkbox);
        //row.appendChild(check);
        row.appendChild(id);
        row.appendChild(name);
        row.appendChild(dataprovider);
        row.appendChild(size);
        row.appendChild(time);
        // row.appendChild(cols)
        //row.appendChild(shared_nodes);

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
          title.innerHTML = "数据集所有列名";
        
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
            popup.appendChild(document.createTextNode("diagnosis,radius_mean,texture_mean,perimeter_mean,area_mean,smoothness_mean,compactness_mean,concavity_mean,concave_points_mean,symmetry_mean,"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("fractal_dimension_mean,radius_se,texture_se,perimeter_se,area_se,smoothness_se,compactness_se,concavity_se,concave_points_se,symmetry_se,fractal_dimension_se,"));
            popup.appendChild(document.createElement("br"));
            popup.appendChild(document.createTextNode("radius_worst,texture_worst,perimeter_worst,area_worst,smoothness_worst,compactness_worst,concavity_worst,concave_points_worst,symmetry_worst,fractal_dimension_worst"));
          }
          else if(value==2){
            popup.appendChild(document.createTextNode("male,age,education,currentSmoker,cigsPerDay,BPMeds,prevalentStroke,prevalentHyp,diabetes,totChol,sysBP,diaBP,BMI,heartRate,glucose,TenYearCHD"));
          }
          else if(value==3){
            popup.appendChild(document.createTextNode("male,age,education,currentSmoker,cigsPerDay,BPMeds,prevalentStroke,prevalentHyp,diabetes,totChol,sysBP,diaBP,BMI,heartRate,glucose,TenYearCHD"));
          }

          var spacer2 = document.createElement("div");
          spacer2.classList.add("spacer2"); // 添加class名称
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
        row.appendChild(cell1);
        datasetsTable.appendChild(row);
      });
    });
}

async function add_datasets() {
  // todo, get info about the dataset
  var datasetLink = document.getElementById("dataset_link").value;
  var datasetName = document.getElementById("dataset_name").value;

  const dataToSend = JSON.stringify({ name: datasetName, link: datasetLink });

  const rawResponse = await fetch("/datasets", {
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    method: "post",
    body: dataToSend,
  });
  // console.log(rawResponse)

  load_datasets_table();
}

async function getDatasets() {
  let datasets = [];
  await fetch("/datasets")
    .then((response) => response.json())
    .then((nodesList) => {
      nodesList.forEach((dataset) => {
        datasets.push([
          dataset.name,
          dataset.size,
          dataset.cols,
          dataset.shared_with,
          dataset.link,
          dataset.description,
        ]);
      });
    });
  return datasets;
}

async function loadAndSplit() {
  var fileToLoad = document.getElementById("fileToLoad").files[0];
  // console.log(fileToLoad)

  var fileReader = new FileReader();
  fileReader.onload = async function (fileLoadedEvent) {
    var data = fileLoadedEvent.target.result;

    // need to load public keys of selected MPC nodes
    let nodes = await getNodes();
    var selectedNodes = getSelectedIndexes("nodes");
    if (selectedNodes.length != 3) {
      console.log("select 3 nodes");
      return;
    }

    let res = SplitCsvText(
      data,
      nodes[selectedNodes[0]][3],
      nodes[selectedNodes[1]][3],
      nodes[selectedNodes[2]][3]
    );
    // result is an array of 4 strings: share for node 0, share for node 1, share for node 2, and description of the columns
    // this should be saved to a file with 4 lines corresponding to the returned values in respected order, see data_management/framingham_tiny_enc.txt
    // console.log("split result", res)
    download(
      res[0] + "\n" + res[1] + "\n" + res[2] + "\n" + res[3] + "\n",
      fileToLoad.name.substring(0, fileToLoad.name.length - 4) +
        "_encrypted_split_data.txt"
    );
  };

  fileReader.readAsText(fileToLoad, "UTF-8");
}
