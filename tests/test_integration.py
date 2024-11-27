#!/usr/bin/env python3
"""Integration tests for the SIEM system."""

import os
import sys
import asyncio
import pytest
import yaml
from datetime import datetime, timedelta
from aiohttp import web
import aiohttp
from aiohttp.test_utils import TestClient, TestServer
import logging
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siem_app import create_app
from models import Base, EventModel, AlertModel, NetworkLogModel
from modules.collectors.windows_event_collector import WindowsEventCollector
from modules.defensive.defensive import DefensiveTools
from modules.offensive.tools import OffensiveTools

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@pytest.fixture
def config():
    """Load test configuration."""
    with open('config/test_config.yaml', 'r') as f:
        return yaml.safe_load(f)

@pytest.fixture
async def db_engine(config):
    """Create test database engine."""
    engine = create_async_engine(config['database']['url'])
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()

@pytest.fixture
async def db_session(db_engine):
    """Create test database session."""
    async_session = sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        yield session

@pytest.fixture
async def app(config, db_engine):
    """Create test application."""
    app = web.Application()
    app['config'] = config
    app['db_engine'] = db_engine
    app['db'] = sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    
    # Setup routes and signal handlers
    from web.routes import setup_routes
    setup_routes(app)
    
    # Freeze signals before startup
    app.freeze()
    
    # Initialize app
    await app.startup()
    yield app
    await app.cleanup()

@pytest.fixture
async def test_client(aiohttp_client, app):
    """Create test client."""
    return await aiohttp_client(app)

@pytest.mark.asyncio
async def test_app_startup(app):
    """Test application startup."""
    assert app is not None
    assert 'config' in app
    assert 'db' in app
    assert 'db_engine' in app

@pytest.mark.asyncio
async def test_windows_collector(app):
    """Test Windows event collector."""
    config = app['config']
    collector = WindowsEventCollector(config)
    
    # Start collector
    await collector.start()
    assert collector.enabled
    assert len(collector.log_types) > 0
    
    # Get events
    events = await collector.get_events()
    assert isinstance(events, list)
    
    # Stop collector
    await collector.stop()

@pytest.mark.asyncio
async def test_defensive_tools(app):
    """Test defensive security tools."""
    config = app['config']
    defensive = DefensiveTools(config)
    
    # Initialize tools
    await defensive.init()
    assert defensive.enabled
    
    # Test threat detection
    threats = await defensive.detect_threats()
    assert isinstance(threats, list)
    
    # Test anomaly detection
    anomalies = await defensive.detect_anomalies()
    assert isinstance(anomalies, list)
    
    # Cleanup
    await defensive.cleanup()

@pytest.mark.asyncio
async def test_offensive_tools(app):
    """Test offensive security tools."""
    config = app['config']
    offensive = OffensiveTools(config)
    
    # Initialize tools
    await offensive.init()
    assert offensive.enabled
    
    # Test scanning
    results = await offensive.scan_network()
    assert isinstance(results, dict)
    
    # Cleanup
    await offensive.cleanup()

@pytest.mark.asyncio
async def test_api_endpoints(test_client):
    """Test API endpoints."""
    # Test events endpoint
    resp = await test_client.get('/api/events')
    assert resp.status == 200
    data = await resp.json()
    assert isinstance(data, list)
    
    # Test alerts endpoint
    resp = await test_client.get('/api/alerts')
    assert resp.status == 200
    data = await resp.json()
    assert isinstance(data, list)
    
    # Test network logs endpoint
    resp = await test_client.get('/api/network_logs')
    assert resp.status == 200
    data = await resp.json()
    assert isinstance(data, list)

@pytest.mark.asyncio
async def test_database_operations(app):
    """Test database operations."""
    async with app['db']() as session:
        # Test event creation
        event = EventModel(
            timestamp=datetime.now(),
            source='test',
            event_type='test',
            severity='info',
            data='Test event'
        )
        session.add(event)
        await session.commit()
        
        # Test alert creation
        alert = AlertModel(
            timestamp=datetime.now(),
            rule_name='test_rule',
            severity='high',
            event_id=event.id,
            status='new'
        )
        session.add(alert)
        await session.commit()
        
        # Test network log creation
        log = NetworkLogModel(
            timestamp=datetime.now(),
            source_ip='127.0.0.1',
            destination_ip='127.0.0.1',
            protocol='TCP',
            data='Test log'
        )
        session.add(log)
        await session.commit()

if __name__ == '__main__':
    pytest.main(['-v', __file__])
