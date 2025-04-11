 
## 准备
操作系统：Linux  
在官网下载与安装Docker Desktop for linux:https://docs.docker.com/get-docker/  
在Vscode中启用Docker插件  
golang 版本 1.17
## 部署
克隆该仓库到本地  
进入`local_test`目录，执行命令  
````docker-compose up````  
即可根据`docker-compose.yml`文件的内容部署3个节点，1个服务器，1个数据提供方  
在本地4100端口即可发起多方计算:http://localhost:4100/  
初始账号和密码：123
## 拓展
当需要添加节点/数据集或作其他修改时，需要克隆到本地的代码中的所有“github.com/chwzx/DataSharingSystem”字符替换成你的github仓库，然后在该仓库中上传修改后的所有代码，同时需要在local_test目录下运行  
````docker-compose build````  
以重新构建镜像  
### 添加节点
当需要添加节点时，在`local_test`目录下的`docker-compose.yml`文件中编写添加新容器的代码，需要注意节点名称必须从目录`key_management/keys_certificates`中包含的证书及证书私钥文件对应的节点中选择，若需要添加其他节点则需要生成新的crt证书，并使用该目录下的`RootCA.key`签名
### 添加数据集
当需要添加数据集时，在`data_provider/datasets`目录下添加csv格式的文件，第一行为每一列的数据名称

