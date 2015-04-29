import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.EsExecutors;
import org.elasticsearch.node.Node;
import org.elasticsearch.node.NodeBuilder;
import org.elasticsearch.test.ElasticsearchSingleNodeTest;
import org.junit.Test;

import java.net.URISyntaxException;

import static org.hamcrest.core.Is.is;

public class CustomParserPluginTest extends ElasticsearchSingleNodeTest {

    private static Node newNode() {
        final Settings settings = ImmutableSettings.builder()
                .put(ClusterName.SETTING, nodeName())
                .put("node.name", nodeName())
                .put(IndexMetaData.SETTING_NUMBER_OF_SHARDS, 1)
                .put(IndexMetaData.SETTING_NUMBER_OF_REPLICAS, 0)
                .put(EsExecutors.PROCESSORS, 1) // limit the number of threads created
                .put("http.enabled", false)
                .put("plugin.types", CustomQueryParserPlugin.class.getName())
//                .put("path.plugins", "target/")
                .put("index.store.type", "ram")
                .put("config.ignore_system_properties", true) // make sure we get what we set :)
                .put("gateway.type", "none").build();

        Node build = NodeBuilder.nodeBuilder().local(true).data(true).settings(
                settings).build();
        build.start();
        assertThat(DiscoveryNode.localNode(build.settings()), is(true));
        return build;
    }


    @Test
    public void jsonParsing() throws URISyntaxException {
        final Client client = newNode().client();
        final SearchResponse test = client.prepareSearch("test-index").setSource(addQuery()).execute().actionGet();
    }

    private String addQuery() {
        return "{\"match_all\":{\"boost\":1.2}}";
    }
}
