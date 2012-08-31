$ ()->
    ncolors = 6

    sniffing = false
    ws = null

    # It's probably bad form to put the templates inline like this.
    sniffTempl = """
        <div class="sniffed-block {{^fromClient}}from-server{{/fromClient}}">
            <div class="desc">
                {{#fromClient}}&rarr;{{/fromClient}}
                {{^fromClient}}&larr;{{/fromClient}}
                {{ id }}
            </div>
            <div class="header">
            {{ #header }}<p>{{ . }}</p>{{ /header }}
            </div>
            <div class="body">
            {{ #body }}<p>{{ . }}</p>{{ /body }}
            </div>
        </div>"""

    setStatus = (text, error)->
        $('#status').text(text).toggleClass('error', !!error)

    processData = (data)->
        if typeof data.header == 'string'
            data.header = data.header.split '\n'
        if typeof data.body == 'string'
            data.body = data.body.split '\n'
        newBlock = $ Mustache.render sniffTempl, data
        if $.isNumeric data.id
            newBlock.addClass "color#{data.id % ncolors}"
        $('#output').append newBlock

    clearOutput = (data)->
        $('#output').html ''

    cleanup = ()->
        if ws
            ws = null
            sniffing = false

    start = ()->
        if sniffing
            return
        sniffing = true
        error = null
        addrs =
            local: $('local').val()
            remote: $('remote').val()
        wsurl = "ws://#{document.location.host}/websocket/"
        websocket = if WebSocket? then WebSocket else MozWebSocket
        ws = new websocket wsurl
        ws.onopen = ()->
            setStatus 'started'
            error = false
        ws.onclose = ()->
            cleanup()
            if not error
                setStatus 'stopped', false
        ws.onmessage = (e)->
            data = JSON.parse e.data
            if data.error
                setStatus data.error, true
                error = true
            else
                processData data

    stop = ()->
        if ws
            ws.close()
        cleanup()
        setStatus "Stopped."

    $('#start').click start
    $('#stop').click stop

#     for i in [0..6]
#         sampleData =
#             id: i
#             fromClient: if (i%2) then true else false
#             header: "This is the header".split "\n"
#             body: "This is the body\nfoo\nbar\nbazwox\n<script>console.log('poo!');</script>".split "\n"
#         processData sampleData
