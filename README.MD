#稻米开放平台#
----

本节对Passport开放平台和SDK进行讲解。

**概念**
----

* **稻米开放平台账号**  

    拥有该账号才能将站点接入到Passport中，一个账号可以同时接入多个站点。

* **AppKey**  
    
	申请了稻米开放平台账号之后会获得一个AppKey，AppKey和开放平台账号的唯一标识符，利用AppKey才可以接入稻米Passport。

* **OpenID**  
    
	当站点用户通过Passport登陆到时，Passport会生成一个用户对应的OpenID，开发者通过这个OpenID跟自己站点的用户系统对接，对接入站点来说，OpenID代表Passport提供的站点用户的唯一标识符。

* **同步回调页**    

    当完成Passport操作之后，Passport会返回用户预设的一个页面，这个页面就叫做“同步回调页”。

* **异步回调页**
    
	也就是Passport SDK目录下的handler页面，该页面会在Passport执行完登陆或注销操作之后调用，开发人员在这里编写站点的用户信息保存、销毁操作。

**接入流程**
----

1. 申请稻米开放平台的的账号，获得AppKey。（详细见“二、如何申请开放平台账号”）

2. 将本SDK下所有文件放到接入站点的目录中，并在需要做登陆验证的页面中引用该SDK。建议编写一个独立的模块引用sdk，并在该页面中调用 IsLogin API判断是否登陆，如果没登陆则调用 ToLogin API跳转到登陆页面。

3. 设置配置文件中的各个参数。

4. 在异步处理页面（handler.php）中的OnLogin和OnLogout函数中编写登陆和注销时需要处理的内容，一般是设置Session。

**如何申请开放平台账号**
----

1. 在oauth表中填入接入用户的名称和AppKey。

2. 在oauth_website表中填入该用户接入的所有站点信息，如果有多个站点则有多条记录，每个站点都需要填入该站点的域名、默认同步回调页、API路径。

**配置文件**
----

开发接口目录下的config.php为配置文件，所有配置信息都包含在$riceappsdk_configs数组中。

* **appkey**
	
	填写你申请的稻米开放平台账号的Appkey。

* **passportdomain**

	Passport服务的地址，不需要修改。

* **client_type**

	接入站点的适配的客户端设备类型，该类型会影响Passport界面的显示样式。
	
		0 - 自适应设备类型
		1 - PC端
		2 - 移动端

* **access_mode**

	接入站点的接入模式。

		1 - 内部接入模式
		2 - 外部接入模式

	使用内部接入模式时，接入站点的必须与Passport同处在一个顶级域，多个内部接入站点之间可以共享登陆状态，也就是说当你在站点A.RICE.EC登陆过之后，进入站点B.RICE.EC时不需要再登陆。
	使用外部接入模式时，接入站点不需要与Passport处在同一个等级域，站点与站点之间不共享登陆状态，也就是说当你在站点C.WAIBU1.COM登陆过之后，进入站点D.WAIBU2.COM仍然需要再登陆。


* **weixin_oauth**

	微信用户授权文件的路径。

* **weixin_appid**

	微信公众号的应用ID。

* **weixin_secret**

	微信公众号的用用秘钥。

* **rootdomain**

	接入站点的根域。

* **adduserbyweixin_unlogin**

	开启在未登陆的情况下将当前微信账号自动绑定到Passprot的功能。

		0 - 未开启（默认）
		1 - 开启

* **sitename**

	子程序名。当一个域名下面有多个子程序时，需要填写该参数，参数内容与站点授权配置的子程序名要一致。默认为空。


#常用API介绍#
-----

**IsLogin**
----

* **描述**

	判断当前是否已经登陆。

* **参数**

		无

* **返回值**

		true - 已登录
		false - 未登陆

**GetOpenID**
----

* **描述**

	获取当前登陆用户的OpenID

* **参数表**
        
		无

* **返回值**

		已经登陆则返回当登陆用户的OpenID，未登陆则返回空字符串。

**GetUserInfo**
----

* **描述**

	获取当前登陆用户的信息

* **参数**

		openid - 登陆用户的OpenID

* **返回值**
	
	若为登陆状态则返回登陆用户的信息，否则返回null。

		StoreID - 商户ID
		RoleType - 角色类别 1-普通用户 2-商户用户
		UserID - 用户ID
		UserName - 用户名称
		NickName - 用户昵称
		Phone - 用户手机号
		OpenID - 用户的OpenID

**ToLogin**
----

* **描述**

	跳转到登陆页面，登陆成功后会跳转回同步回调页。

* **参数**

		redirecturi - 同步回调页地址，只需要回调页面部分，不需要完整的地址。

* **返回值**

		无

**ToRegister**
----

* **描述**

	跳转到注册页面，注册成功后会跳转回同步回调页。

* **参数**

		redirecturi - 同步回调页地址，只需要回调页面部分，不需要完整的地址。

* **返回值**

		无

**Logout**
----

* **描述**

	注销用户登陆。

* **参数**

		无

* **返回值**

		无

**ChangePassword**
----

* **描述**

	跳转到修改密码页面，修改成功会返回同步回调页，只有处于登陆状态时才能使用该功能。

* **参数**

		redirecturi - 同步回调页地址，只需要回调页面部分，不需要完整的地址。

* **返回值**

		无

**RebindPhone**
----

* **描述**

	跳转到重新绑定手机号页面，绑定成功会返回同步回调页，只有处于登陆状态时才能使用该功能。

* **参数**

		redirecturi - 同步回调页地址，只需要回调页面部分，不需要完整的地址。

* **返回值**

		无

**AddUser**
----

* **描述**

	通过手机号码生成一个新用户，并返回用户信息。

* **参数**

		phone - 手机号码

* **返回值**

		StoreID - 商户ID
		RoleType - 角色类别 1-普通用户 2-商户用户
		UserID - 用户ID
		UserName - 用户名称
		NickName - 用户昵称
		Phone - 用户手机号
		OpenID - 用户的OpenID

**Login**
----

* **描述**

	直接登陆，不需要进入登陆页面，登陆成功后会返回同步回调页。

* **参数**

		redirecturi - 同步回调页地址，只需要回调页面部分，不需要完整的地址
        username - 用户名
        password - 密码

* **返回值**

		无

**GetStoreID**
----

* **描述**

	获取当前的商户ID。

* **参数**

		无

* **返回值**

		当前商户的ID，0代表整个平台。

**SetStoreID**
----

* **描述**

	修改当前的商户ID。

* **参数**

		storeid - 商户ID，0代表整个平台

* **返回值**

		无

**AuthorizeToUser**
----

* **描述**

	为用户授权。

* **参数**

		userid - 用户ID
        rolecode - 角色编码

* **返回值**

		1 - 授权成功
		0 - 授权失败

**CheckPermissions**
----

* **描述**

	检查用户是否拥有当前页面的访问权限。

* **参数**

		无

* **返回值**

		无

**CheckPermissionsByUrl**
----

* **描述**

	检查用户是否拥有指定服务的访问权限。

* **参数**

		serviceurl - 服务的唯一标识符

* **返回值**

		true - 有权限
		false - 没有权限

**GetStore**
----

* **描述**

	获取当前的商家信息。

* **参数**

		无

* **返回值**

		StoreID - 商户ID
        StoreName - 商户名称
        ProviderID - 服务提供者ID
        ProviderName - 服务提供者名称
        TempletID - 模板ID
        TempletCode - 模板编码
        TempletName - 模板名称
        LayoutID - 布局ID
        LayoutCode - 布局编码
        LayoutName - 布局名称

**GetStoreServices**
----

* **描述**

	获取当前用户的后台权限列表。

* **参数**

		openid - Passport分配给当前用户的openid。

* **返回值**

	返回值为一个数组，没有权限的情况下返回null。数组中实体的格式为：

		ServiceID - 服务ID
		ServiceName - 服务名称 
		ServiceUrl - 服务的唯一资源定位符

**BindPhone**
----

* **描述**

	绑定手机号码到当前登陆的用户。

* **参数**

		mobile - 手机号码。

* **返回值**

	返回值为true代表绑定成功，如果绑定失败会返回错误信息。