## API Client

This Bit9 API client is an ORM-like library to make querying and accessing data
from Bit9's REST API easier. The wrapper borrows heavily from the design of
[NDB](https://cloud.google.com/appengine/docs/standard/python/ndb/), a Datastore
client.

Bit9 models are defined as Python classes and are instantiated to contain data
returned from Bit9. Properties on the Bit9 models are accessed just as normal
Python properties (albeit snake-case) and querying is done using a builder-like
syntax.

All calls to the API are passed an instance of `api.Context`. This is class
handles the actual request to the API via the `ExecuteRequest()` method. However
the only thing required of a `Context` class is that it provide this method. It
can be overridden to e.g. have extra intrumentation or use a different transport
medium. You can find the `Context` implementation in [`context.py`](context.py).

### Model Definitions

The model definitions in [`api.py`](api.py) are automatically generated from the
Bit9 API documentation page using the
[`build_from_docs.py`](scripts/build_from_docs.py) script.

The submitted model types are a subset of all models available in the Bit9
interface: Only the models currently required by Upvote are present.

If other models are required or the current ones need to be updated, the
`build_from_docs.py` script can be run passing in the raw HTML of the Bit9 docs
page (present at `/api/bit9platform/v1` on the Bit9 frontend server) as well as
the `--objects_to_output` flag with the names of all model names to be
generated. The output of the script can then replace the content of `api.py`.

### Querying

The library supports several different methods for interfacing with Bit9 models:

-   `get()`: Retrieves a Bit9 entity by ID
-   `put()`: Writes the content of a `Model` instance to Bit9
-   `delete()`: Deletes a Bit9 entity by ID
-   `update()`: Updates properties on a Bit9 entity by ID
-   `query()` -> `execute()` or `count()`: Performs a query on a Bit9 model

#### Basic Example

A query can be executed using the following builder-type syntax:

```python
CONTEXT = api.Context('https://my-bit9-server.foocorp.com', 'my-api-key', 30)
events = (
    api.Event.query()
    .filter(api.Event.file_catalog_id == 12345)
    .execute(CONTEXT))
```

This returns a list of events where `fileCatalogId` is 12345.

#### Ordering

The `order()` method can be used to achieve the `ORDER BY` behavior in SQL:

```python
events = (
    api.Event.query()
    .filter(api.Event.file_catalog_id == 12345)
    .order(api.Event.id)
    .execute(CONTEXT))
```

This returns the events ordered by the entity ID in ascending order. To query in
descending order, prefix the property with a minus sign:

```python
    .order(-api.Event.id)
```

#### Counting

To only return the counts of the entities matching the query, change the
`execute()` method to `count()`:

```python
num_events = (
    api.Event.query()
    .filter(api.Event.file_catalog_id == 12345)
    .count(CONTEXT))
```

#### Expands

Expands are a feature of the Bit9 API that is equivalent to SQL's foreign-key
expansions. An expand clause will cause the specified ID property to be expanded
to the full model for each object returned in the query. This is often desirable
as it reduces the number of API requests needed to extract the same information
from each query result.

The following is the semantics of the feature implemented in this library:

```python
# Query for Events. Returned Events will have Computer models attached.
events = (
    api.Event.query()
    .filter(api.Event.file_catalog_id == 12345)
    .expand(api.Event.computer_id)
    .execute(CONTEXT))
# Extract the returned Computer model. No additional API query is made.
computer = events[0].get_expand(api.Event.computer_id)
```

#### Filter Combinators

When filtering a query, it might be necessary to have multiple clauses on the
same property e.g. I want "fileCatalogId" to be either 12345 or 67890. This can
be accomplished using builtin Python operators:

<!--
The pipe character in the snippet below is a (U+2223, Symbol divides) because
GitHub's Markdown parser currently does not support escaped pipes.
-->

```python
events = (
    api.Event.query()
    .filter((api.Event.file_catalog_id == 12345) ǀ (api.Event.file_catalog_id == 67890))
    .execute(CONTEXT))
```

**NOTE**: The extra parentheses around each filter clause are *required*.

At current, only disjunction ("OR") is supported but additional combinators
should be quite straightforward to implement. See
[`query_nodes.py`](query_nodes.py) for the implementation.

### Unsupported Features

The library does not currently support Bit9 group-by queries.
