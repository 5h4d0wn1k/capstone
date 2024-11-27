from aiohttp import web
import json

routes = web.RouteTableDef()

@routes.get('/api/events')
async def get_events(request):
    db = request.app['db']
    events = await db.get_recent_events()
    return web.json_response([event.to_dict() for event in events])

@routes.get('/api/alerts')
async def get_alerts(request):
    db = request.app['db']
    alerts = await db.get_recent_alerts()
    return web.json_response([alert.to_dict() for alert in alerts])

@routes.get('/api/network_logs')
async def get_network_logs(request):
    db = request.app['db']
    logs = await db.get_recent_network_logs()
    return web.json_response([log.to_dict() for log in logs])

@routes.post('/api/alerts/{alert_id}/status')
async def update_alert(request):
    alert_id = int(request.match_info['alert_id'])
    data = await request.json()
    status = data.get('status')
    if not status:
        raise web.HTTPBadRequest(text='Status is required')
    
    db = request.app['db']
    await db.update_alert_status(alert_id, status)
    return web.json_response({'status': 'updated'})

@routes.get('/')
async def serve_dashboard(request):
    return web.FileResponse('templates/dashboard.html')

def setup_routes(app):
    """Setup routes for the application."""
    app.router.add_routes(routes)
    return app
