import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.indices.query.IndicesQueriesModule;
import org.elasticsearch.plugins.AbstractPlugin;

public class CustomQueryParserPlugin extends AbstractPlugin {
    public static final String PLUGIN_NAME = "custom_query";
    private final Settings settings;

    @Inject
    public CustomQueryParserPlugin(Settings settings) {
        this.settings = settings;
    }

    @Override
    public String name() {
        return PLUGIN_NAME;
    }

    @Override
    public String description() {
        return "custom plugin";
    }

    public void onModule(IndicesQueriesModule module) {
        module.addQuery(new CustomQueryParser(settings));
    }
}