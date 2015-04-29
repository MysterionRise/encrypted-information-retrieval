import junit.framework.TestCase;
import org.codelibs.elasticsearch.runner.ElasticsearchClusterRunner;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.ImmutableSettings.Builder;
import org.elasticsearch.index.query.QueryBuilders;

import static org.codelibs.elasticsearch.runner.ElasticsearchClusterRunner.newConfigs;

public class CustomParserPluginTest2 extends TestCase {

    private ElasticsearchClusterRunner runner;

    @Override
    protected void setUp() throws Exception {
        // create runner instance
        runner = new ElasticsearchClusterRunner();
        // create ES nodes
        runner.onBuild(new ElasticsearchClusterRunner.Builder() {
            @Override
            public void build(final int number, final Builder settingsBuilder) {
            }
        }).build(newConfigs().ramIndexStore().numOfNode(1));

        // wait for yellow status
        runner.ensureYellow();
    }

    @Override
    protected void tearDown() throws Exception {
        // close runner
        runner.close();
        // delete all files
        runner.clean();
    }

    public void test_jsonParsing() throws Exception {
        final String index = "test_index";

        runner.createIndex(index, ImmutableSettings.builder().build());
        runner.ensureYellow(index);

        String json = "{" +
                "\"user\":\"kimchy\"," +
                "\"postDate\":\"2013-01-30\"," +
                "\"message\":\"trying out Elasticsearch\"" +
                "}";
        IndexResponse response = runner.client().prepareIndex(index, "tweet", "1")
                .setSource(json)
                .execute()
                .actionGet();
        SearchResponse searchResponse = runner.client().prepareSearch(index)
                .setQuery(QueryBuilders.termQuery("user", "kimchy"))
                .setFrom(0).setSize(60).setExplain(true)
                .execute()
                .actionGet();
        System.out.println(searchResponse.toString());
    }
}