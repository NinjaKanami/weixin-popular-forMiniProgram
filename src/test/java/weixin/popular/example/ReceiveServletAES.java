package weixin.popular.example;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.Charset;

import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.qq.weixin.mp.aes.AesException;
import com.qq.weixin.mp.aes.WXBizMsgCrypt;

import weixin.popular.bean.message.EventMessage;
import weixin.popular.bean.xmlmessage.XMLMessage;
import weixin.popular.bean.xmlmessage.XMLTextMessage;
import weixin.popular.support.ExpireKey;
import weixin.popular.support.expirekey.DefaultExpireKey;
import weixin.popular.util.SignatureUtil;
import weixin.popular.util.StreamUtils;
import weixin.popular.util.XMLConverUtil;

/**
 * 服务端事件消息接收  加密模式
 *
 * @author Yi
 */
public class ReceiveServletAES extends HttpServlet {

    /**
     *
     */
    private static final long serialVersionUID = 1L;

    private String appId = "";                //appid 通过微信后台获取
    private String token = "test";            //通过微信后台获取

    private String encodingToken = "";        //Token(令牌)   通过微信后台获取
    private String encodingAesKey = "";        //EncodingAESKey(消息加解密密钥) 通过微信后台获取

    //重复通知过滤
    private static ExpireKey expireKey = new DefaultExpireKey();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        ServletInputStream inputStream = request.getInputStream();
        ServletOutputStream outputStream = response.getOutputStream();
        String signature = request.getParameter("signature");
        String timestamp = request.getParameter("timestamp");
        String nonce = request.getParameter("nonce");
        String echostr = request.getParameter("echostr");

        //加密模式
        String encrypt_type = request.getParameter("encrypt_type");
        String msg_signature = request.getParameter("msg_signature");

        WXBizMsgCrypt wxBizMsgCrypt = null;
        //加密方式
        boolean isAes = "aes".equals(encrypt_type);
        if (isAes) {
            try {
                wxBizMsgCrypt = new WXBizMsgCrypt(encodingToken, encodingAesKey, appId);
            } catch (AesException e) {
                e.printStackTrace();
            }
        }

        EventMessage eventMessage = null;
        if (isAes) {
            //若为安全模式消息推送
            try {
                //获取XML数据（含加密参数）
                String postData = StreamUtils.copyToString(inputStream, Charset.forName("utf-8"));
                //解密XML 数据
                assert wxBizMsgCrypt != null;
                String xmlData = wxBizMsgCrypt.decryptMsg(msg_signature, timestamp, nonce, postData);
                //XML 转换为bean 对象
                eventMessage = XMLConverUtil.convertToObject(EventMessage.class, xmlData);
            } catch (AesException e) {
                e.printStackTrace();
            }
        } else {
            //若非安全模式消息推送 则为验证消息推送 或 明文模式消息推送
            if (signature == null) {
                System.out.println("The request signature is null");
                return;
            }
            //验证请求签名
            if (!signature.equals(SignatureUtil.generateEventMessageSignature(encodingToken, timestamp, nonce))) {
                System.out.println("The request signature is invalid");
                return;
            }
            //首次请求申请验证,返回echostr
            if (echostr != null) {
                echostr = URLDecoder.decode(echostr, "utf-8");
                outputStreamWrite(outputStream, echostr);
                return;
            }
            //明文模式消息推送
            if (inputStream != null) {
                //XML 转换为bean 对象
                eventMessage = XMLConverUtil.convertToObject(EventMessage.class, inputStream);
            }
        }

        String key = eventMessage.getFromUserName() + "__"
                + eventMessage.getToUserName() + "__"
                + eventMessage.getMsgId() + "__"
                + eventMessage.getCreateTime();
        if (expireKey.exists(key)) {
            //重复通知不作处理
            return;
        } else {
            expireKey.add(key);
        }

        //创建回复
        XMLMessage xmlTextMessage = new XMLTextMessage(
                eventMessage.getFromUserName(),
                eventMessage.getToUserName(),
                "你好");
        //回复
        xmlTextMessage.outputStreamWrite(outputStream, wxBizMsgCrypt);
    }

    /**
     * 数据流输出
     *
     * @param outputStream
     * @param text
     * @return
     */
    private boolean outputStreamWrite(OutputStream outputStream, String text) {
        try {
            outputStream.write(text.getBytes("utf-8"));
        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return false;
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return false;
        }
        return true;
    }
}
