$(function(){
  if(Cookies.get('username')&&Cookies.get('token')){
    username_html='<li class="dropdown"><a href="#" class="dropdown-toggle" data-toggle="dropdown" id="user">'+atob(Cookies.get('username'))+'<b class="caret"></b></a><ul class="dropdown-menu"><li><a href="/myhome?token='+Cookies.get('token')+'">个人中心</a></li><li class="divider"></li><li><a href="/logout?token='+Cookies.get('token')+'">退出</a></li></li>'
    $("#login").html(username_html)
  }
});

//status
$(function () {
        var t_server = $("#table_server").bootstrapTable({
            url: 'http://'+location.host+'/api/status',
            method: 'post',
            dataType: "json",
            striped: true,//设置为 true 会有隔行变色效果
            undefinedText: "空",//当数据为 undefined 时显示的字符
            pagination: true, //分页
            showToggle: "true",//是否显示 切换试图（table/card）按钮
            showColumns: "true",//是否显示 内容列下拉框
            pageNumber: 1,//如果设置了分页，首页页码
            pageSize: 20,//如果设置了分页，页面数据条数
            pageList: [5, 10, 20, 40],  //如果设置了分页，设置可供选择的页面数据条数。设置为All 则显示所有记录。
            paginationPreText: '‹',//指定分页条中上一页按钮的图标或文字,这里是<
            paginationNextText: '›',//指定分页条中下一页按钮的图标或文字,这里是>
            search: false,
            data_local: "zh-US",//表格汉化
            sidePagination: "server", //服务端处理分页
            queryParams: function (params) {//自定义参数，这里的参数是传给后台的，我这是是分页用的
                return {//这里的params是table提供的
                    offset: params.offset,//从数据库第几条记录开始
                    listrows: params.limit//找多少条
                };
            },
            idField: "userId",//指定主键列
            columns: [
                {
                    title: 'run_id',
                    field: 'run_id',
                    align: 'center'
                },
                {
                    title: 'problem_id',
                    field: 'problem_id',
                    align: 'center'
                },
                {
                    title: 'nickname',
                    field: 'nickname',
                    align: 'center',
                    formatter: function (value, row, index) {
                        return atob(row.nickname);
                    }
                },
                {
                    title: 'status',
                    field: 'status',
                    align: 'center',
                    formatter: function (value, row, index) {
                        switch(row.status){case 0:pro_result="OrzAccept";break;case 1:pro_result="Compile Error";break;case 2:pro_result="Wrong Answer";break;case 3:pro_result="Time Limit Exceeded";break;case 4:pro_result="Presentation Error";break;case 5:pro_result="Runtime Error";break;case 6:pro_result="System error";break;case -1:pro_result="waiting";break;default:pro_result="Unknow Error";}
                        return pro_result
                    }
                },
                {
                    title: 'time',
                    field: 'time',
                    align: 'center',
                },
                {
                    title: ' compile',
                    field: 'compile',
                    align: 'center',
                    formatter: function (value, row, index) {
                        switch(row.compile){case 0:compilename="gcc";break;case 1:compilename="g++";break;case 2:compilename="python";break;default:compilename="Unknow Compile";}
                        if(row.nickname==Cookies.get("username")){
                            return "<a href=/api/source?run_id="+row.run_id+"&token="+Cookies.get("token")+">"+compilename+"</a>"
                        }else{
                            return compilename
                        }
                    }
                }
            ]
        });

        t_server.on('load-success.bs.table', function (data) {
            console.log("load success");
            $(".pull-right").css("display", "block");
        });
    });


    //problem
$(function () {
        var t_problem = $("#problem").bootstrapTable({
            url: 'http://'+location.host+'/api/problem',
            method: 'post',
            dataType: "json",
            striped: true,//设置为 true 会有隔行变色效果
            undefinedText: "空",//当数据为 undefined 时显示的字符
            pagination: true, //分页
            showToggle: "true",//是否显示 切换试图（table/card）按钮
            showColumns: "true",//是否显示 内容列下拉框
            pageNumber: 1,//如果设置了分页，首页页码
            pageSize: 20,//如果设置了分页，页面数据条数
            pageList: [5, 10, 20, 40],  //如果设置了分页，设置可供选择的页面数据条数。设置为All 则显示所有记录。
            paginationPreText: '‹',//指定分页条中上一页按钮的图标或文字,这里是<
            paginationNextText: '›',//指定分页条中下一页按钮的图标或文字,这里是>
            search: false,
            data_local: "zh-US",//表格汉化
            sidePagination: "server", //服务端处理分页
            queryParams: function (params) {//自定义参数，这里的参数是传给后台的，我这是是分页用的
                return {//这里的params是table提供的
                    offset: params.offset,//从数据库第几条记录开始
                    listrows: params.limit//找多少条
                };
            },
            idField: "userId",//指定主键列
            columns: [
                {
                    title: 'problem_id',
                    field: 'problem_id',
                    align: 'center',
                    formatter: function (value, row, index) {
                        return "<a href=/api/getprobleminfo?problem_id="+row.problem_id+">"+value+"</a>"
                    }
                },
                {
                    title: 'title',
                    field: 'title',
                    align: 'center',
                    formatter: function (value, row, index) {
                        return "<a href=/api/getprobleminfo?problem_id="+row.problem_id+">"+value+"</a>"
                    }
                }
            ]
        });

        t_problem.on('load-success.bs.table', function (data) {
            console.log("load success");
            $(".pull-right").css("display", "block");
        });
    });

 function submit(){
 compile_id=$("#compile_id").val()
code=$("#code").val()
submit_problem_id=$("#problem_id").val()
name=Cookies.get("username")
token=Cookies.get("token")
if (!token){alert("请先登录");return false;}
if(compile_id==""){
alert("请选择编译选项");return false;}
url=location.href
$.post(url,JSON.stringify({"code":code,"compiler_id":compile_id,"problem_id":submit_problem_id,"token":token,"username":name,"time":Date()}),function (results){
    	if(results.status){
    		alert("提交成功，请等待判题");window.location.href="http://"+location.host+"/status.html"
    	}else{
    		alert("提交失败，请重试");
    	}
    },"json");
 }

 //status
$(function () {
        var t_home = $("#home").bootstrapTable({
            url: location.href,
            method: 'post',
            dataType: "json",
            striped: true,//设置为 true 会有隔行变色效果
            undefinedText: "空",//当数据为 undefined 时显示的字符
            pagination: true, //分页
            showToggle: "true",//是否显示 切换试图（table/card）按钮
            showColumns: "true",//是否显示 内容列下拉框
            pageNumber: 1,//如果设置了分页，首页页码
            pageSize: 20,//如果设置了分页，页面数据条数
            pageList: [5, 10, 20, 40],  //如果设置了分页，设置可供选择的页面数据条数。设置为All 则显示所有记录。
            paginationPreText: '‹',//指定分页条中上一页按钮的图标或文字,这里是<
            paginationNextText: '›',//指定分页条中下一页按钮的图标或文字,这里是>
            search: false,
            data_local: "zh-US",//表格汉化
            sidePagination: "server", //服务端处理分页
            queryParams: function (params) {//自定义参数，这里的参数是传给后台的，我这是是分页用的
                return {//这里的params是table提供的
                    offset: params.offset,//从数据库第几条记录开始
                    listrows: params.limit//找多少条
                };
            },
            idField: "userId",//指定主键列
            columns: [
                {
                    title: 'run_id',
                    field: 'run_id',
                    align: 'center'
                },
                {
                    title: 'problem_id',
                    field: 'problem_id',
                    align: 'center'
                },
                {
                    title: 'nickname',
                    field: 'nickname',
                    align: 'center',
                    formatter: function (value, row, index) {
                        return atob(row.nickname);
                    }
                },
                {
                    title: 'status',
                    field: 'status',
                    align: 'center',
                    formatter: function (value, row, index) {
                        switch(row.status){case 0:pro_result="OrzAccept";break;case 1:pro_result="Compile Error";break;case 2:pro_result="Wrong Answer";break;case 3:pro_result="Time Limit Exceeded";break;case 4:pro_result="Presentation Error";break;case 5:pro_result="Runtime Error";break;case 6:pro_result="System error";break;case -1:pro_result="waiting";break;default:pro_result="Unknow Error";}
                        return pro_result
                    }
                },
                {
                    title: 'time',
                    field: 'time',
                    align: 'center',
                },
                {
                    title: ' compile',
                    field: 'compile',
                    align: 'center',
                    formatter: function (value, row, index) {
                        switch(row.compile){case 0:compilename="gcc";break;case 1:compilename="g++";break;case 2:compilename="python";break;default:compilename="Unknow Compile";}
                        if(row.nickname==Cookies.get("username")){
                            return "<a href=/api/source?run_id="+row.run_id+"&token="+Cookies.get("token")+">"+compilename+"</a>"
                        }else{
                            return compilename
                        }
                    }
                }
            ]
        });

        t_home.on('load-success.bs.table', function (data) {
            console.log("load success");
            $(".pull-right").css("display", "block");
        });
    });