# RichOnline 官网设计契约

## 1. 来源与方向
继承 item-catalog 的原版图片、八类资料表、无动画和16px中文正文。2026-10-12通过浏览器访问原版大宇官网 http://richol.softstar.com.tw/gameinfo/index-gameinfo-3.aspx ，确认玩法、股票、房地产、操作、会员与奇迹栏目，以及红黄暖色配白色正文。参考其游戏门户信息层级，采用本项目暖色令牌；不是像素复刻。旧站Flash已失效，不复制空白Flash区或历史活动。首页与资料页共用一个index.html外壳、导航与页脚，数据按路由延迟加载。

## 2. 用户任务
老玩家从游戏跳转后领取代币或修改密码；新玩家注册后回到游戏；查资料的玩家直接进入图鉴。导航顺序：首页、游戏资料、注册账号、修改密码、领取代币。

## 3. Tokens
颜色：background #fff、panel #faf7f1、border #e8ddd0、text #24292f、muted #626a73、accent #982627、selected #fff1d4、gold #f5c84d、hero-start #fff8e5、row-hover #fffaf0、danger #9b2525。字体 Microsoft YaHei / PingFang SC / system-ui；正文16px、辅助14px、三级20px、二级28px、主标题40px（手机28px）；行高1.7。间距4/8/12/16/24/32/48/64px。页面最大1120px，表单最大560px，圆角4px、表单容器8px；表面由细灰边界分隔，无阴影。按钮及输入最小44px。

地图预览保持240×180px展示框、object-fit:contain；图片完整展示，链接文字与原版预览并列，窄屏叠放。

## 4. 布局
文档负责纵向滚动；导航在窄屏单独横向滚动；资料表沿用自己的横向滚动容器。主栏 max-width + 居中内边距；首页两栏在760px以下叠放。正文和表单 min-width:0，长文本换行，不通过隐藏溢出来掩盖布局错误。

## 5. 可复用原语及状态
SiteHeader/SiteFooter：各服务页共享；导航含 aria-current。ServiceLink：标题、说明和可辨识链接。FormField：可见 label、辅助文字、必填提示、autocomplete、focus-visible。SubmitButton：默认、hover、disabled/处理中；禁止重复提交。Notice：普通、成功、错误，使用文字及 role=status，不单靠颜色。RoleSelect：查询成功后展示所属角色及余额，账号或密码改变即失效。资料页沿用 table/columns/pagination 原语。

## 6. 内容与安全交互
页面明确每次领取10000代币、余额必须低于10000、无需付费与审核。注册使用游戏可兼容的账号/密码字符；修改密码必须验证原密码。成功后清除密码输入，不存浏览器存储。领取网络不确定时保留操作编号用于幂等重试；不得把断网报成明确未发放。账号服务强制 HTTPS，旧 HTTP 入口仅跳转。

## 7. 可访问性与性能
语义 landmark、跳到正文、输入标签和可见焦点；反馈 aria-live；触屏目标至少44px；无动画、无外部字体、无广告或跟踪代码。首页不加载资料站大JSON和音频，资料页保留分页及 preload=none。

## 8. 验证边界
用户仅允许静态检查和编译，不新增或运行测试、不启动本机服务。故本轮不执行 skill 的组件浏览器展示、Lighthouse 和视觉 QA，不声称这些门禁通过；后续实机反馈用于继续修正。非 React 项目不安装 React 开发依赖。

## 9. 官网资料统一改版
统一SiteHeader/SiteFooter和页面1120px宽度。GameplayLink复用三栏入口，窄屏单栏；暖色首屏与原版地图预览提供游戏识别。CatalogNav保留八分类横向滚动，Table/Pagination沿用资料表列宽、图片与音频尺寸，不另建站点导航或iframe。分类、分页滚动属于正文，账号页保持原验证和反馈状态。采用一套实际存在的导航，未开放的下载、活动、客服入口不造假。
浏览器只用于用户要求的外部历史网站研究；按既有约束未运行本项目视觉测试、Lighthouse或账号测试，保留为验收边界。
