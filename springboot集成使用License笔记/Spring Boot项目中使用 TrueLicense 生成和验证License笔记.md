# 一，简介
License，即版权许可证，一般用于收费软件给付费用户提供的访问许可证明。根据应用部署位置的不同，一般可以分为以下两种情况讨论：

 - 应用部署在开发者自己的云服务器上。这种情况下用户通过账号登录的形式远程访问，因此只需要在账号登录的时候校验目标账号的有效期、访问权限等信息即可。
 - 
   应用部署在客户的内网环境。因为这种情况开发者无法控制客户的网络环境，也不能保证应用所在服务器可以访问外网，因此通常的做法是使用服务器许可文件，在应用启动的时候加载证书，然后在登录或者其他关键操作的地方校验证书的有效性。
# 二， 使用 TrueLicense 生成License
## 1，在pom.xml中添加关键依赖

```xml
<dependency>
    <groupId>de.schlichtherle.truelicense</groupId>
    <artifactId>truelicense-core</artifactId>
    <version>1.33</version>
    <scope>provided</scope>
</dependency>
```
## 2，校验自定义的License参数
`TrueLicense`的 `de.schlichtherle.license.LicenseManager `类自带的`verify`方法只校验了我们后面颁发的许可文件的生效和过期时间，然而在实际项目中我们可能需要额外校验应用部署的服务器的IP地址、MAC地址、CPU序列号、主板序列号等信息，因此我们需要复写框架的部分方法以实现校验自定义参数的目的。

首先需要添加一个自定义的可被允许的服务器硬件信息的实体类（如果校验其他参数，可自行补充）：

```java
package cn.zifangsky.license;

import java.io.Serializable;
import java.util.List;

/**
 * 自定义需要校验的License参数
 *
 * @author zifangsky
 * @date 2018/4/23
 * @since 1.0.0
 */
public class LicenseCheckModel implements Serializable{

    private static final long serialVersionUID = 8600137500316662317L;
    /**
     * 可被允许的IP地址
     */
    private List<String> ipAddress;

    /**
     * 可被允许的MAC地址
     */
    private List<String> macAddress;

    /**
     * 可被允许的CPU序列号
     */
    private String cpuSerial;

    /**
     * 可被允许的主板序列号
     */
    private String mainBoardSerial;

    //省略setter和getter方法

    @Override
    public String toString() {
        return "LicenseCheckModel{" +
                "ipAddress=" + ipAddress +
                ", macAddress=" + macAddress +
                ", cpuSerial='" + cpuSerial + '\'' +
                ", mainBoardSerial='" + mainBoardSerial + '\'' +
                '}';
    }
}
```
其次，添加一个`License`生成类需要的参数：

```java
package cn.zifangsky.license;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.io.Serializable;
import java.util.Date;

/**
 * License生成类需要的参数
 *
 * @author zifangsky
 * @date 2018/4/19
 * @since 1.0.0
 */
public class LicenseCreatorParam implements Serializable {

    private static final long serialVersionUID = -7793154252684580872L;
    /**
     * 证书subject
     */
    private String subject;

    /**
     * 密钥别称
     */
    private String privateAlias;

    /**
     * 密钥密码（需要妥善保管，不能让使用者知道）
     */
    private String keyPass;

    /**
     * 访问秘钥库的密码
     */
    private String storePass;

    /**
     * 证书生成路径
     */
    private String licensePath;

    /**
     * 密钥库存储路径
     */
    private String privateKeysStorePath;

    /**
     * 证书生效时间
     */
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date issuedTime = new Date();

    /**
     * 证书失效时间
     */
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date expiryTime;

    /**
     * 用户类型
     */
    private String consumerType = "user";

    /**
     * 用户数量
     */
    private Integer consumerAmount = 1;

    /**
     * 描述信息
     */
    private String description = "";

    /**
     * 额外的服务器硬件校验信息
     */
    private LicenseCheckModel licenseCheckModel;

    //省略setter和getter方法

    @Override
    public String toString() {
        return "LicenseCreatorParam{" +
                "subject='" + subject + '\'' +
                ", privateAlias='" + privateAlias + '\'' +
                ", keyPass='" + keyPass + '\'' +
                ", storePass='" + storePass + '\'' +
                ", licensePath='" + licensePath + '\'' +
                ", privateKeysStorePath='" + privateKeysStorePath + '\'' +
                ", issuedTime=" + issuedTime +
                ", expiryTime=" + expiryTime +
                ", consumerType='" + consumerType + '\'' +
                ", consumerAmount=" + consumerAmount +
                ", description='" + description + '\'' +
                ", licenseCheckModel=" + licenseCheckModel +
                '}';
    }
}
```
添加抽象类`AbstractServerInfos`，用户获取服务器的硬件信息：

```java
package cn.zifangsky.license;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * 用于获取客户服务器的基本信息，如：IP、Mac地址、CPU序列号、主板序列号等
 *
 * @author zifangsky
 * @date 2018/4/23
 * @since 1.0.0
 */
public abstract class AbstractServerInfos {
    private static Logger logger = LogManager.getLogger(AbstractServerInfos.class);

    /**
     * 组装需要额外校验的License参数
     * @author zifangsky
     * @date 2018/4/23 14:23
     * @since 1.0.0
     * @return demo.LicenseCheckModel
     */
    public LicenseCheckModel getServerInfos(){
        LicenseCheckModel result = new LicenseCheckModel();

        try {
            result.setIpAddress(this.getIpAddress());
            result.setMacAddress(this.getMacAddress());
            result.setCpuSerial(this.getCPUSerial());
            result.setMainBoardSerial(this.getMainBoardSerial());
        }catch (Exception e){
            logger.error("获取服务器硬件信息失败",e);
        }

        return result;
    }

    /**
     * 获取IP地址
     * @author zifangsky
     * @date 2018/4/23 11:32
     * @since 1.0.0
     * @return java.util.List<java.lang.String>
     */
    protected abstract List<String> getIpAddress() throws Exception;

    /**
     * 获取Mac地址
     * @author zifangsky
     * @date 2018/4/23 11:32
     * @since 1.0.0
     * @return java.util.List<java.lang.String>
     */
    protected abstract List<String> getMacAddress() throws Exception;

    /**
     * 获取CPU序列号
     * @author zifangsky
     * @date 2018/4/23 11:35
     * @since 1.0.0
     * @return java.lang.String
     */
    protected abstract String getCPUSerial() throws Exception;

    /**
     * 获取主板序列号
     * @author zifangsky
     * @date 2018/4/23 11:35
     * @since 1.0.0
     * @return java.lang.String
     */
    protected abstract String getMainBoardSerial() throws Exception;

    /**
     * 获取当前服务器所有符合条件的InetAddress
     * @author zifangsky
     * @date 2018/4/23 17:38
     * @since 1.0.0
     * @return java.util.List<java.net.InetAddress>
     */
    protected List<InetAddress> getLocalAllInetAddress() throws Exception {
        List<InetAddress> result = new ArrayList<>(4);

        // 遍历所有的网络接口
        for (Enumeration networkInterfaces = NetworkInterface.getNetworkInterfaces(); networkInterfaces.hasMoreElements(); ) {
            NetworkInterface iface = (NetworkInterface) networkInterfaces.nextElement();
            // 在所有的接口下再遍历IP
            for (Enumeration inetAddresses = iface.getInetAddresses(); inetAddresses.hasMoreElements(); ) {
                InetAddress inetAddr = (InetAddress) inetAddresses.nextElement();

                //排除LoopbackAddress、SiteLocalAddress、LinkLocalAddress、MulticastAddress类型的IP地址
                if(!inetAddr.isLoopbackAddress() /*&& !inetAddr.isSiteLocalAddress()*/
                        && !inetAddr.isLinkLocalAddress() && !inetAddr.isMulticastAddress()){
                    result.add(inetAddr);
                }
            }
        }

        return result;
    }

    /**
     * 获取某个网络接口的Mac地址
     * @author zifangsky
     * @date 2018/4/23 18:08
     * @since 1.0.0
     * @param
     * @return void
     */
    protected String getMacByInetAddress(InetAddress inetAddr){
        try {
            byte[] mac = NetworkInterface.getByInetAddress(inetAddr).getHardwareAddress();
            StringBuffer stringBuffer = new StringBuffer();

            for(int i=0;i<mac.length;i++){
                if(i != 0) {
                    stringBuffer.append("-");
                }

                //将十六进制byte转化为字符串
                String temp = Integer.toHexString(mac[i] & 0xff);
                if(temp.length() == 1){
                    stringBuffer.append("0" + temp);
                }else{
                    stringBuffer.append(temp);
                }
            }

            return stringBuffer.toString().toUpperCase();
        } catch (SocketException e) {
            e.printStackTrace();
        }

        return null;
    }

}

```
获取客户Linux服务器的基本信息：

```java
package cn.zifangsky.license;

import org.apache.commons.lang3.StringUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 用于获取客户Linux服务器的基本信息
 *
 * @author zifangsky
 * @date 2018/4/23
 * @since 1.0.0
 */
public class LinuxServerInfos extends AbstractServerInfos {

    @Override
    protected List<String> getIpAddress() throws Exception {
        List<String> result = null;

        //获取所有网络接口
        List<InetAddress> inetAddresses = getLocalAllInetAddress();

        if(inetAddresses != null && inetAddresses.size() > 0){
            result = inetAddresses.stream().map(InetAddress::getHostAddress).distinct().map(String::toLowerCase).collect(Collectors.toList());
        }

        return result;
    }

    @Override
    protected List<String> getMacAddress() throws Exception {
        List<String> result = null;

        //1. 获取所有网络接口
        List<InetAddress> inetAddresses = getLocalAllInetAddress();

        if(inetAddresses != null && inetAddresses.size() > 0){
            //2. 获取所有网络接口的Mac地址
            result = inetAddresses.stream().map(this::getMacByInetAddress).distinct().collect(Collectors.toList());
        }

        return result;
    }

    @Override
    protected String getCPUSerial() throws Exception {
        //序列号
        String serialNumber = "";

        //使用dmidecode命令获取CPU序列号
        String[] shell = {"/bin/bash","-c","dmidecode -t processor | grep 'ID' | awk -F ':' '{print $2}' | head -n 1"};
        Process process = Runtime.getRuntime().exec(shell);
        process.getOutputStream().close();

        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

        String line = reader.readLine().trim();
        if(StringUtils.isNotBlank(line)){
            serialNumber = line;
        }

        reader.close();
        return serialNumber;
    }

    @Override
    protected String getMainBoardSerial() throws Exception {
        //序列号
        String serialNumber = "";

        //使用dmidecode命令获取主板序列号
        String[] shell = {"/bin/bash","-c","dmidecode | grep 'Serial Number' | awk -F ':' '{print $2}' | head -n 1"};
        Process process = Runtime.getRuntime().exec(shell);
        process.getOutputStream().close();

        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

        String line = reader.readLine().trim();
        if(StringUtils.isNotBlank(line)){
            serialNumber = line;
        }

        reader.close();
        return serialNumber;
    }
}

```
获取客户Windows服务器的基本信息：

```java
package cn.zifangsky.license;

import java.net.InetAddress;
import java.util.List;
import java.util.Scanner;
import java.util.stream.Collectors;

/**
 * 用于获取客户Windows服务器的基本信息
 *
 * @author zifangsky
 * @date 2018/4/23
 * @since 1.0.0
 */
public class WindowsServerInfos extends AbstractServerInfos {

    @Override
    protected List<String> getIpAddress() throws Exception {
        List<String> result = null;

        //获取所有网络接口
        List<InetAddress> inetAddresses = getLocalAllInetAddress();

        if(inetAddresses != null && inetAddresses.size() > 0){
            result = inetAddresses.stream().map(InetAddress::getHostAddress).distinct().map(String::toLowerCase).collect(Collectors.toList());
        }

        return result;
    }

    @Override
    protected List<String> getMacAddress() throws Exception {
        List<String> result = null;

        //1. 获取所有网络接口
        List<InetAddress> inetAddresses = getLocalAllInetAddress();

        if(inetAddresses != null && inetAddresses.size() > 0){
            //2. 获取所有网络接口的Mac地址
            result = inetAddresses.stream().map(this::getMacByInetAddress).distinct().collect(Collectors.toList());
        }

        return result;
    }

    @Override
    protected String getCPUSerial() throws Exception {
        //序列号
        String serialNumber = "";

        //使用WMIC获取CPU序列号
        Process process = Runtime.getRuntime().exec("wmic cpu get processorid");
        process.getOutputStream().close();
        Scanner scanner = new Scanner(process.getInputStream());

        if(scanner.hasNext()){
            scanner.next();
        }

        if(scanner.hasNext()){
            serialNumber = scanner.next().trim();
        }

        scanner.close();
        return serialNumber;
    }

    @Override
    protected String getMainBoardSerial() throws Exception {
        //序列号
        String serialNumber = "";

        //使用WMIC获取主板序列号
        Process process = Runtime.getRuntime().exec("wmic baseboard get serialnumber");
        process.getOutputStream().close();
        Scanner scanner = new Scanner(process.getInputStream());

        if(scanner.hasNext()){
            scanner.next();
        }

        if(scanner.hasNext()){
            serialNumber = scanner.next().trim();
        }

        scanner.close();
        return serialNumber;
    }
}
```
自定义LicenseManager，用于增加额外的服务器硬件信息校验：

```java
package cn.zifangsky.license;

import de.schlichtherle.license.LicenseContent;
import de.schlichtherle.license.LicenseContentException;
import de.schlichtherle.license.LicenseManager;
import de.schlichtherle.license.LicenseNotary;
import de.schlichtherle.license.LicenseParam;
import de.schlichtherle.license.NoLicenseInstalledException;
import de.schlichtherle.xml.GenericCertificate;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.beans.XMLDecoder;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.List;

/**
 * 自定义LicenseManager，用于增加额外的服务器硬件信息校验
 *
 * @author zifangsky
 * @date 2018/4/23
 * @since 1.0.0
 */
public class CustomLicenseManager extends LicenseManager{
    private static Logger logger = LogManager.getLogger(CustomLicenseManager.class);

    //XML编码
    private static final String XML_CHARSET = "UTF-8";
    //默认BUFSIZE
    private static final int DEFAULT_BUFSIZE = 8 * 1024;

    public CustomLicenseManager() {

    }

    public CustomLicenseManager(LicenseParam param) {
        super(param);
    }

    /**
     * 复写create方法
     * @author zifangsky
     * @date 2018/4/23 10:36
     * @since 1.0.0
     * @param
     * @return byte[]
     */
    @Override
    protected synchronized byte[] create(
            LicenseContent content,
            LicenseNotary notary)
            throws Exception {
        initialize(content);
        this.validateCreate(content);
        final GenericCertificate certificate = notary.sign(content);
        return getPrivacyGuard().cert2key(certificate);
    }

    /**
     * 复写install方法，其中validate方法调用本类中的validate方法，校验IP地址、Mac地址等其他信息
     * @author zifangsky
     * @date 2018/4/23 10:40
     * @since 1.0.0
     * @param
     * @return de.schlichtherle.license.LicenseContent
     */
    @Override
    protected synchronized LicenseContent install(
            final byte[] key,
            final LicenseNotary notary)
            throws Exception {
        final GenericCertificate certificate = getPrivacyGuard().key2cert(key);

        notary.verify(certificate);
        final LicenseContent content = (LicenseContent)this.load(certificate.getEncoded());
        this.validate(content);
        setLicenseKey(key);
        setCertificate(certificate);

        return content;
    }

    /**
     * 复写verify方法，调用本类中的validate方法，校验IP地址、Mac地址等其他信息
     * @author zifangsky
     * @date 2018/4/23 10:40
     * @since 1.0.0
     * @param
     * @return de.schlichtherle.license.LicenseContent
     */
    @Override
    protected synchronized LicenseContent verify(final LicenseNotary notary)
            throws Exception {
        GenericCertificate certificate = getCertificate();

        // Load license key from preferences,
        final byte[] key = getLicenseKey();
        if (null == key){
            throw new NoLicenseInstalledException(getLicenseParam().getSubject());
        }

        certificate = getPrivacyGuard().key2cert(key);
        notary.verify(certificate);
        final LicenseContent content = (LicenseContent)this.load(certificate.getEncoded());
        this.validate(content);
        setCertificate(certificate);

        return content;
    }

    /**
     * 校验生成证书的参数信息
     * @author zifangsky
     * @date 2018/5/2 15:43
     * @since 1.0.0
     * @param content 证书正文
     */
    protected synchronized void validateCreate(final LicenseContent content)
            throws LicenseContentException {
        final LicenseParam param = getLicenseParam();

        final Date now = new Date();
        final Date notBefore = content.getNotBefore();
        final Date notAfter = content.getNotAfter();
        if (null != notAfter && now.after(notAfter)){
            throw new LicenseContentException("证书失效时间不能早于当前时间");
        }
        if (null != notBefore && null != notAfter && notAfter.before(notBefore)){
            throw new LicenseContentException("证书生效时间不能晚于证书失效时间");
        }
        final String consumerType = content.getConsumerType();
        if (null == consumerType){
            throw new LicenseContentException("用户类型不能为空");
        }
    }


    /**
     * 复写validate方法，增加IP地址、Mac地址等其他信息校验
     * @author zifangsky
     * @date 2018/4/23 10:40
     * @since 1.0.0
     * @param content LicenseContent
     */
    @Override
    protected synchronized void validate(final LicenseContent content)
            throws LicenseContentException {
        //1. 首先调用父类的validate方法
        super.validate(content);

        //2. 然后校验自定义的License参数
        //License中可被允许的参数信息
        LicenseCheckModel expectedCheckModel = (LicenseCheckModel) content.getExtra();
        //当前服务器真实的参数信息
        LicenseCheckModel serverCheckModel = getServerInfos();

        if(expectedCheckModel != null && serverCheckModel != null){
            //校验IP地址
            if(!checkIpAddress(expectedCheckModel.getIpAddress(),serverCheckModel.getIpAddress())){
                throw new LicenseContentException("当前服务器的IP没在授权范围内");
            }

            //校验Mac地址
            if(!checkIpAddress(expectedCheckModel.getMacAddress(),serverCheckModel.getMacAddress())){
                throw new LicenseContentException("当前服务器的Mac地址没在授权范围内");
            }

            //校验主板序列号
            if(!checkSerial(expectedCheckModel.getMainBoardSerial(),serverCheckModel.getMainBoardSerial())){
                throw new LicenseContentException("当前服务器的主板序列号没在授权范围内");
            }

            //校验CPU序列号
            if(!checkSerial(expectedCheckModel.getCpuSerial(),serverCheckModel.getCpuSerial())){
                throw new LicenseContentException("当前服务器的CPU序列号没在授权范围内");
            }
        }else{
            throw new LicenseContentException("不能获取服务器硬件信息");
        }
    }


    /**
     * 重写XMLDecoder解析XML
     * @author zifangsky
     * @date 2018/4/25 14:02
     * @since 1.0.0
     * @param encoded XML类型字符串
     * @return java.lang.Object
     */
    private Object load(String encoded){
        BufferedInputStream inputStream = null;
        XMLDecoder decoder = null;
        try {
            inputStream = new BufferedInputStream(new ByteArrayInputStream(encoded.getBytes(XML_CHARSET)));

            decoder = new XMLDecoder(new BufferedInputStream(inputStream, DEFAULT_BUFSIZE),null,null);

            return decoder.readObject();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } finally {
            try {
                if(decoder != null){
                    decoder.close();
                }
                if(inputStream != null){
                    inputStream.close();
                }
            } catch (Exception e) {
                logger.error("XMLDecoder解析XML失败",e);
            }
        }

        return null;
    }

    /**
     * 获取当前服务器需要额外校验的License参数
     * @author zifangsky
     * @date 2018/4/23 14:33
     * @since 1.0.0
     * @return demo.LicenseCheckModel
     */
    private LicenseCheckModel getServerInfos(){
        //操作系统类型
        String osName = System.getProperty("os.name").toLowerCase();
        AbstractServerInfos abstractServerInfos = null;

        //根据不同操作系统类型选择不同的数据获取方法
        if (osName.startsWith("windows")) {
            abstractServerInfos = new WindowsServerInfos();
        } else if (osName.startsWith("linux")) {
            abstractServerInfos = new LinuxServerInfos();
        }else{//其他服务器类型
            abstractServerInfos = new LinuxServerInfos();
        }

        return abstractServerInfos.getServerInfos();
    }

    /**
     * 校验当前服务器的IP/Mac地址是否在可被允许的IP范围内<br/>
     * 如果存在IP在可被允许的IP/Mac地址范围内，则返回true
     * @author zifangsky
     * @date 2018/4/24 11:44
     * @since 1.0.0
     * @return boolean
     */
    private boolean checkIpAddress(List<String> expectedList,List<String> serverList){
        if(expectedList != null && expectedList.size() > 0){
            if(serverList != null && serverList.size() > 0){
                for(String expected : expectedList){
                    if(serverList.contains(expected.trim())){
                        return true;
                    }
                }
            }

            return false;
        }else {
            return true;
        }
    }

    /**
     * 校验当前服务器硬件（主板、CPU等）序列号是否在可允许范围内
     * @author zifangsky
     * @date 2018/4/24 14:38
     * @since 1.0.0
     * @return boolean
     */
    private boolean checkSerial(String expectedSerial,String serverSerial){
        if(StringUtils.isNotBlank(expectedSerial)){
            if(StringUtils.isNotBlank(serverSerial)){
                if(expectedSerial.equals(serverSerial)){
                    return true;
                }
            }

            return false;
        }else{
            return true;
        }
    }

}
```
最后是License生成类，用于生成License证书：

```java
package cn.zifangsky.license;

import de.schlichtherle.license.CipherParam;
import de.schlichtherle.license.DefaultCipherParam;
import de.schlichtherle.license.DefaultLicenseParam;
import de.schlichtherle.license.KeyStoreParam;
import de.schlichtherle.license.LicenseContent;
import de.schlichtherle.license.LicenseManager;
import de.schlichtherle.license.LicenseParam;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.text.MessageFormat;
import java.util.prefs.Preferences;

/**
 * License生成类
 *
 * @author zifangsky
 * @date 2018/4/19
 * @since 1.0.0
 */
public class LicenseCreator {
    private static Logger logger = LogManager.getLogger(LicenseCreator.class);
    private final static X500Principal DEFAULT_HOLDER_AND_ISSUER = new X500Principal("CN=localhost, OU=localhost, O=localhost, L=SH, ST=SH, C=CN");
    private LicenseCreatorParam param;

    public LicenseCreator(LicenseCreatorParam param) {
        this.param = param;
    }

    /**
     * 生成License证书
     * @author zifangsky
     * @date 2018/4/20 10:58
     * @since 1.0.0
     * @return boolean
     */
    public boolean generateLicense(){
        try {
            LicenseManager licenseManager = new CustomLicenseManager(initLicenseParam());
            LicenseContent licenseContent = initLicenseContent();

            licenseManager.store(licenseContent,new File(param.getLicensePath()));

            return true;
        }catch (Exception e){
            logger.error(MessageFormat.format("证书生成失败：{0}",param),e);
            return false;
        }
    }

    /**
     * 初始化证书生成参数
     * @author zifangsky
     * @date 2018/4/20 10:56
     * @since 1.0.0
     * @return de.schlichtherle.license.LicenseParam
     */
    private LicenseParam initLicenseParam(){
        Preferences preferences = Preferences.userNodeForPackage(LicenseCreator.class);

        //设置对证书内容加密的秘钥
        CipherParam cipherParam = new DefaultCipherParam(param.getStorePass());

        KeyStoreParam privateStoreParam = new CustomKeyStoreParam(LicenseCreator.class
                ,param.getPrivateKeysStorePath()
                ,param.getPrivateAlias()
                ,param.getStorePass()
                ,param.getKeyPass());

        LicenseParam licenseParam = new DefaultLicenseParam(param.getSubject()
                ,preferences
                ,privateStoreParam
                ,cipherParam);

        return licenseParam;
    }

    /**
     * 设置证书生成正文信息
     * @author zifangsky
     * @date 2018/4/20 10:57
     * @since 1.0.0
     * @return de.schlichtherle.license.LicenseContent
     */
    private LicenseContent initLicenseContent(){
        LicenseContent licenseContent = new LicenseContent();
        licenseContent.setHolder(DEFAULT_HOLDER_AND_ISSUER);
        licenseContent.setIssuer(DEFAULT_HOLDER_AND_ISSUER);

        licenseContent.setSubject(param.getSubject());
        licenseContent.setIssued(param.getIssuedTime());
        licenseContent.setNotBefore(param.getIssuedTime());
        licenseContent.setNotAfter(param.getExpiryTime());
        licenseContent.setConsumerType(param.getConsumerType());
        licenseContent.setConsumerAmount(param.getConsumerAmount());
        licenseContent.setInfo(param.getDescription());

        //扩展校验服务器硬件信息
        licenseContent.setExtra(param.getLicenseCheckModel());

        return licenseContent;
    }

}
```
## 3，添加一个生成证书的Controller：

这个Controller对外提供了两个RESTful接口，分别是「获取服务器硬件信息」和「生成证书」，示例代码如下：

```java
package cn.zifangsky.controller;

import cn.zifangsky.license.AbstractServerInfos;
import cn.zifangsky.license.LicenseCheckModel;
import cn.zifangsky.license.LicenseCreator;
import cn.zifangsky.license.LicenseCreatorParam;
import cn.zifangsky.license.LinuxServerInfos;
import cn.zifangsky.license.WindowsServerInfos;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 *
 * 用于生成证书文件，不能放在给客户部署的代码里
 * @author zifangsky
 * @date 2018/4/26
 * @since 1.0.0
 */
@RestController
@RequestMapping("/license")
public class LicenseCreatorController {

    /**
     * 证书生成路径
     */
    @Value("${license.licensePath}")
    private String licensePath;

    /**
     * 获取服务器硬件信息
     * @author zifangsky
     * @date 2018/4/26 13:13
     * @since 1.0.0
     * @param osName 操作系统类型，如果为空则自动判断
     * @return com.ccx.models.license.LicenseCheckModel
     */
    @RequestMapping(value = "/getServerInfos",produces = {MediaType.APPLICATION_JSON_UTF8_VALUE})
    public LicenseCheckModel getServerInfos(@RequestParam(value = "osName",required = false) String osName) {
        //操作系统类型
        if(StringUtils.isBlank(osName)){
            osName = System.getProperty("os.name");
        }
        osName = osName.toLowerCase();

        AbstractServerInfos abstractServerInfos = null;

        //根据不同操作系统类型选择不同的数据获取方法
        if (osName.startsWith("windows")) {
            abstractServerInfos = new WindowsServerInfos();
        } else if (osName.startsWith("linux")) {
            abstractServerInfos = new LinuxServerInfos();
        }else{//其他服务器类型
            abstractServerInfos = new LinuxServerInfos();
        }

        return abstractServerInfos.getServerInfos();
    }

    /**
     * 生成证书
     * @author zifangsky
     * @date 2018/4/26 13:13
     * @since 1.0.0
     * @param param 生成证书需要的参数，如：{"subject":"ccx-models","privateAlias":"privateKey","keyPass":"5T7Zz5Y0dJFcqTxvzkH5LDGJJSGMzQ","storePass":"3538cef8e7","licensePath":"C:/Users/zifangsky/Desktop/license.lic","privateKeysStorePath":"C:/Users/zifangsky/Desktop/privateKeys.keystore","issuedTime":"2018-04-26 14:48:12","expiryTime":"2018-12-31 00:00:00","consumerType":"User","consumerAmount":1,"description":"这是证书描述信息","licenseCheckModel":{"ipAddress":["192.168.245.1","10.0.5.22"],"macAddress":["00-50-56-C0-00-01","50-7B-9D-F9-18-41"],"cpuSerial":"BFEBFBFF000406E3","mainBoardSerial":"L1HF65E00X9"}}
     * @return java.util.Map<java.lang.String,java.lang.Object>
     */
    @RequestMapping(value = "/generateLicense",produces = {MediaType.APPLICATION_JSON_UTF8_VALUE})
    public Map<String,Object> generateLicense(@RequestBody(required = true) LicenseCreatorParam param) {
        Map<String,Object> resultMap = new HashMap<>(2);

        if(StringUtils.isBlank(param.getLicensePath())){
            param.setLicensePath(licensePath);
        }

        LicenseCreator licenseCreator = new LicenseCreator(param);
        boolean result = licenseCreator.generateLicense();

        if(result){
            resultMap.put("result","ok");
            resultMap.put("msg",param);
        }else{
            resultMap.put("result","error");
            resultMap.put("msg","证书文件生成失败！");
        }
        return resultMap;
    }
}
```
# 三，使用JDK自带的 keytool 工具生成公私钥证书库
假如我们设置公钥库密码为：public_password1234，私钥库密码为：private_password1234，则生成命令如下：

```java
#生成命令
keytool -genkeypair -keysize 1024 -validity 3650 -alias "privateKey" -keystore "privateKeys.keystore" -storepass "public_password1234" -keypass "private_password1234" -dname "CN=localhost, OU=localhost, O=localhost, L=SH, ST=SH, C=CN"

#导出命令
keytool -exportcert -alias "privateKey" -keystore "privateKeys.keystore" -storepass "public_password1234" -file "certfile.cer"

#导入命令
keytool -import -alias "publicCert" -file "certfile.cer" -keystore "publicCerts.keystore" -storepass "public_password1234"
```
上述命令执行完成之后，会在当前路径下生成三个文件，分别是：`privateKeys.keystore`、`publicCerts.keystore`、`certfile.cer`。<font color="blue">其中文件`certfile.cer`不再需要可以删除，文件`privateKeys.keystore`用于当前的 `ServerDemo `项目给客户生成`license`文件，而文件`publicCerts.keystore`则随应用代码部署到客户服务器，用户解密`license`文件并校验其许可信息。</font>
# 四，为客户生成license文件
将 ServerDemo  项目部署到客户服务器，通过以下接口获取服务器的硬件信息（等license文件生成后需要删除这个项目。当然也可以通过命令手动获取客户服务器的硬件信息，然后在开发者自己的电脑上生成license文件）：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200623143308764.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NDAwMTk2NQ==,size_16,color_FFFFFF,t_70)
然后生成license文件：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200623143350167.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NDAwMTk2NQ==,size_16,color_FFFFFF,t_70)
<font color="blue">请求时需要在Header中添加一个 Content-Type ，其值为：application/json;charset=UTF-8</font>。参数示例如下：

```java
{
	"subject": "license_demo",
	"privateAlias": "privateKey",
	"keyPass": "private_password1234",
	"storePass": "public_password1234",
	"licensePath": "C:/Users/zifangsky/Desktop/license_demo/license.lic",
	"privateKeysStorePath": "C:/Users/zifangsky/Desktop/license_demo/privateKeys.keystore",
	"issuedTime": "2018-07-10 00:00:01",
	"expiryTime": "2019-12-31 23:59:59",
	"consumerType": "User",
	"consumerAmount": 1,
	"description": "这是证书描述信息",
	"licenseCheckModel": {
		"ipAddress": ["192.168.245.1", "10.0.5.22"],
		"macAddress": ["00-50-56-C0-00-01", "50-7B-9D-F9-18-41"],
		"cpuSerial": "BFEBFBFF000406E3",
		"mainBoardSerial": "L1HF65E00X9"
	}
}
```
如果请求成功，那么最后会在` licensePath` 参数设置的路径生成一个` license.lic `的文件，这个文件就是给客户部署代码的服务器许可文件。
# 五，给客户部署的应用中添加License校验
## 1，添加License校验类需要的参数

```java
package cn.zifangsky.license;

/**
 * License校验类需要的参数
 *
 * @author zifangsky
 * @date 2018/4/20
 * @since 1.0.0
 */
public class LicenseVerifyParam {

    /**
     * 证书subject
     */
    private String subject;

    /**
     * 公钥别称
     */
    private String publicAlias;

    /**
     * 访问公钥库的密码
     */
    private String storePass;

    /**
     * 证书生成路径
     */
    private String licensePath;

    /**
     * 密钥库存储路径
     */
    private String publicKeysStorePath;

    public LicenseVerifyParam() {

    }

    public LicenseVerifyParam(String subject, String publicAlias, String storePass, String licensePath, String publicKeysStorePath) {
        this.subject = subject;
        this.publicAlias = publicAlias;
        this.storePass = storePass;
        this.licensePath = licensePath;
        this.publicKeysStorePath = publicKeysStorePath;
    }

    //省略setter和getter方法

    @Override
    public String toString() {
        return "LicenseVerifyParam{" +
                "subject='" + subject + '\'' +
                ", publicAlias='" + publicAlias + '\'' +
                ", storePass='" + storePass + '\'' +
                ", licensePath='" + licensePath + '\'' +
                ", publicKeysStorePath='" + publicKeysStorePath + '\'' +
                '}';
    }
}
```
然后再添加License校验类：

```java
package cn.zifangsky.license;

import de.schlichtherle.license.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.text.DateFormat;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.prefs.Preferences;

/**
 * License校验类
 *
 * @author zifangsky
 * @date 2018/4/20
 * @since 1.0.0
 */
public class LicenseVerify {
    private static Logger logger = LogManager.getLogger(LicenseVerify.class);

    /**
     * 安装License证书
     * @author zifangsky
     * @date 2018/4/20 16:26
     * @since 1.0.0
     */
    public synchronized LicenseContent install(LicenseVerifyParam param){
        LicenseContent result = null;
        DateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        //1. 安装证书
        try{
            LicenseManager licenseManager = LicenseManagerHolder.getInstance(initLicenseParam(param));
            licenseManager.uninstall();

            result = licenseManager.install(new File(param.getLicensePath()));
            logger.info(MessageFormat.format("证书安装成功，证书有效期：{0} - {1}",format.format(result.getNotBefore()),format.format(result.getNotAfter())));
        }catch (Exception e){
            logger.error("证书安装失败！",e);
        }

        return result;
    }

    /**
     * 校验License证书
     * @author zifangsky
     * @date 2018/4/20 16:26
     * @since 1.0.0
     * @return boolean
     */
    public boolean verify(){
        LicenseManager licenseManager = LicenseManagerHolder.getInstance(null);
        DateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        //2. 校验证书
        try {
            LicenseContent licenseContent = licenseManager.verify();
//            System.out.println(licenseContent.getSubject());

            logger.info(MessageFormat.format("证书校验通过，证书有效期：{0} - {1}",format.format(licenseContent.getNotBefore()),format.format(licenseContent.getNotAfter())));
            return true;
        }catch (Exception e){
            logger.error("证书校验失败！",e);
            return false;
        }
    }

    /**
     * 初始化证书生成参数
     * @author zifangsky
     * @date 2018/4/20 10:56
     * @since 1.0.0
     * @param param License校验类需要的参数
     * @return de.schlichtherle.license.LicenseParam
     */
    private LicenseParam initLicenseParam(LicenseVerifyParam param){
        Preferences preferences = Preferences.userNodeForPackage(LicenseVerify.class);

        CipherParam cipherParam = new DefaultCipherParam(param.getStorePass());

        KeyStoreParam publicStoreParam = new CustomKeyStoreParam(LicenseVerify.class
                ,param.getPublicKeysStorePath()
                ,param.getPublicAlias()
                ,param.getStorePass()
                ,null);

        return new DefaultLicenseParam(param.getSubject()
                ,preferences
                ,publicStoreParam
                ,cipherParam);
    }

}

```
## 2，添加Listener，用于在项目启动的时候安装License证书

```java
package cn.zifangsky.license;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;

/**
 * 在项目启动时安装证书
 *
 * @author zifangsky
 * @date 2018/4/24
 * @since 1.0.0
 */
@Component
public class LicenseCheckListener implements ApplicationListener<ContextRefreshedEvent> {
    private static Logger logger = LogManager.getLogger(LicenseCheckListener.class);

    /**
     * 证书subject
     */
    @Value("${license.subject}")
    private String subject;

    /**
     * 公钥别称
     */
    @Value("${license.publicAlias}")
    private String publicAlias;

    /**
     * 访问公钥库的密码
     */
    @Value("${license.storePass}")
    private String storePass;

    /**
     * 证书生成路径
     */
    @Value("${license.licensePath}")
    private String licensePath;

    /**
     * 密钥库存储路径
     */
    @Value("${license.publicKeysStorePath}")
    private String publicKeysStorePath;

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        //root application context 没有parent
        ApplicationContext context = event.getApplicationContext().getParent();
        if(context == null){
            if(StringUtils.isNotBlank(licensePath)){
                logger.info("++++++++ 开始安装证书 ++++++++");

                LicenseVerifyParam param = new LicenseVerifyParam();
                param.setSubject(subject);
                param.setPublicAlias(publicAlias);
                param.setStorePass(storePass);
                param.setLicensePath(licensePath);
                param.setPublicKeysStorePath(publicKeysStorePath);

                LicenseVerify licenseVerify = new LicenseVerify();
                //安装证书
                licenseVerify.install(param);

                logger.info("++++++++ 证书安装结束 ++++++++");
            }
        }
    }
}
```
注：上面代码使用参数信息如下所示：

```java
#License相关配置
license.subject=license_demo
license.publicAlias=publicCert
license.storePass=public_password1234
license.licensePath=C:/Users/zifangsky/Desktop/license_demo/license.lic
license.publicKeysStorePath=C:/Users/zifangsky/Desktop/license_demo/publicCerts.keystore
```
## 3，添加拦截器，用于在登录的时候校验License证书

```java
package cn.zifangsky.license;

import com.alibaba.fastjson.JSON;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * LicenseCheckInterceptor
 *
 * @author zifangsky
 * @date 2018/4/25
 * @since 1.0.0
 */
public class LicenseCheckInterceptor extends HandlerInterceptorAdapter{
    private static Logger logger = LogManager.getLogger(LicenseCheckInterceptor.class);

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        LicenseVerify licenseVerify = new LicenseVerify();

        //校验证书是否有效
        boolean verifyResult = licenseVerify.verify();

        if(verifyResult){
            return true;
        }else{
            response.setCharacterEncoding("utf-8");
            Map<String,String> result = new HashMap<>(1);
            result.put("result","您的证书无效，请核查服务器是否取得授权或重新申请证书！");

            response.getWriter().write(JSON.toJSONString(result));

            return false;
        }
    }

}
```
## 4，添加登录页面并测试

```html
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <meta content="text/html;charset=UTF-8"/>
    <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>登录页面</title>
    <script src="https://cdn.bootcss.com/jquery/2.2.4/jquery.min.js"></script>
    <link href="https://cdn.bootcss.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.bootcss.com/font-awesome/4.7.0/css/font-awesome.min.css" rel="stylesheet">
    <script src="https://cdn.bootcss.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
    <link rel="stylesheet" th:href="@{/css/style.css}"/>

    <script>
        //回车登录
        function enterlogin(e) {
            var key = window.event ? e.keyCode : e.which;
            if (key === 13) {
                userLogin();
            }
        }

        //用户密码登录
        function userLogin() {
            //获取用户名、密码
            var username = $("#username").val();
            var password = $("#password").val();

            if (username == null || username === "") {
                $("#errMsg").text("请输入登陆用户名！");
                $("#errMsg").attr("style", "display:block");
                return;
            }
            if (password == null || password === "") {
                $("#errMsg").text("请输入登陆密码！");
                $("#errMsg").attr("style", "display:block");
                return;
            }

            $.ajax({
                url: "/check",
                type: "POST",
                dataType: "json",
                async: false,
                data: {
                    "username": username,
                    "password": password
                },
                success: function (data) {
                    if (data.code == "200") {
                        $("#errMsg").attr("style", "display:none");
                        window.location.href = '/userIndex';
                    } else if (data.result != null) {
                        $("#errMsg").text(data.result);
                        $("#errMsg").attr("style", "display:block");
                    } else {
                        $("#errMsg").text(data.msg);
                        $("#errMsg").attr("style", "display:block");
                    }
                }
            });
        }
    </script>
</head>
<body onkeydown="enterlogin(event);">
<div class="container">
    <div class="form row">
        <div class="form-horizontal col-md-offset-3" id="login_form">
            <h3 class="form-title">LOGIN</h3>
            <div class="col-md-9">
                <div class="form-group">
                    <i class="fa fa-user fa-lg"></i>
                    <input class="form-control required" type="text" placeholder="Username" id="username"
                           name="username" autofocus="autofocus" maxlength="20"/>
                </div>
                <div class="form-group">
                    <i class="fa fa-lock fa-lg"></i>
                    <input class="form-control required" type="password" placeholder="Password" id="password"
                           name="password" maxlength="8"/>
                </div>
                <div class="form-group">
                    <span class="errMsg" id="errMsg" style="display: none">错误提示</span>
                </div>
                <div class="form-group col-md-offset-9">
                    <button type="submit" class="btn btn-success pull-right" name="submit" onclick="userLogin()">登录
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>
</body>
</html>
```
启动项目，可以发现之前生成的license证书可以正常使用：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200623143949716.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NDAwMTk2NQ==,size_16,color_FFFFFF,t_70)
这时访问 http://127.0.0.1:7080/login ，可以正常登录：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200623144001307.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NDAwMTk2NQ==,size_16,color_FFFFFF,t_70)
重新生成license证书，并设置很短的有效期。
重新启动ClientDemo，并再次登录，可以发现爆以下提示信息：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200623144019719.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200623144030153.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NDAwMTk2NQ==,size_16,color_FFFFFF,t_70)

至此，关于使用 TrueLicense 生成和验证License就结束了


