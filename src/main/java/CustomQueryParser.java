import org.apache.lucene.search.MatchAllDocsQuery;
import org.apache.lucene.search.Query;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.query.QueryParseContext;
import org.elasticsearch.index.query.QueryParser;
import org.elasticsearch.index.query.QueryParsingException;

import java.io.IOException;

public class CustomQueryParser implements QueryParser {
    public CustomQueryParser(Settings settings) {
    }

    @Override
    public String[] names() {
        return new String[0];
    }

    @Override
    public Query parse(QueryParseContext parseContext) throws IOException, QueryParsingException {
        return new MatchAllDocsQuery();
    }
}
