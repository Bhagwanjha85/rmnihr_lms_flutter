from django.core.cache import cache
from .models import SystemLogo, Visitor, TemplateConfig

def active_logos(request):
    logos = cache.get('active_logos_cache')
    if logos is None:
        logos = list(SystemLogo.objects.filter(is_active=True).order_by('created_at'))
        cache.set('active_logos_cache', logos, 3600)
    return {
        'active_logos': logos
    }

def visitor_count(request):
    try:
        from reports.firebase_sync import ensure_database_hydrated, sync_visitor_to_firebase
        ensure_database_hydrated()
    except Exception:
        pass

    cached_count = cache.get('visitor_count_cache')
    
    # 1. Skip counting authenticated staff/admin users
    if request.user and request.user.is_authenticated:
        if cached_count is None:
            cached_count = Visitor.objects.count()
            cache.set('visitor_count_cache', cached_count, 300)
        return {
            'visitor_count': cached_count
        }

    # 2. Skip counting bots, crawlers, and script engines
    user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
    bot_keywords = ['bot', 'spider', 'crawler', 'slurp', 'curl', 'wget', 'python', 'http-client', 'postman', 'headless']
    if any(keyword in user_agent for keyword in bot_keywords):
        if cached_count is None:
            cached_count = Visitor.objects.count()
            cache.set('visitor_count_cache', cached_count, 300)
        return {
            'visitor_count': cached_count
        }

    # 3. Extract real client IP, resolving proxies if any
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
        
    # 4. Filter out private/local loopback IPs (e.g. Render internal routing)
    is_private = False
    if ip:
        if ip in ['127.0.0.1', '::1', 'localhost']:
            is_private = True
        elif ip.startswith('10.') or ip.startswith('192.168.'):
            is_private = True
        elif ip.startswith('172.'):
            try:
                parts = ip.split('.')
                if len(parts) == 4:
                    second_octet = int(parts[1])
                    if 16 <= second_octet <= 31:
                        is_private = True
            except ValueError:
                pass

    # 5. Only create a new visitor record if this browser session hasn't been counted yet
    if ip and not is_private:
        if not request.session.get('has_counted_visit'):
            try:
                v = Visitor.objects.create(ip_address=ip)
                request.session['has_counted_visit'] = True
                try:
                    from reports.firebase_sync import sync_visitor_to_firebase
                    sync_visitor_to_firebase(v)
                except Exception:
                    pass

                if cached_count is not None:
                    try:
                        cached_count = cache.incr('visitor_count_cache')
                    except ValueError:
                        cached_count = Visitor.objects.count()
                        cache.set('visitor_count_cache', cached_count, 300)
                else:
                    cached_count = Visitor.objects.count()
                    cache.set('visitor_count_cache', cached_count, 300)
            except Exception:
                pass
            
    if cached_count is None:
        cached_count = Visitor.objects.count()
        cache.set('visitor_count_cache', cached_count, 300)
        
    return {
        'visitor_count': cached_count
    }

def template_config(request):
    config = cache.get('template_config_cache')
    if config is None:
        config = TemplateConfig.get_solo()
        cache.set('template_config_cache', config, 3600)
    return {
        'template_config': config
    }
