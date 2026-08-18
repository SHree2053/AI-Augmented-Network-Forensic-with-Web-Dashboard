from django.contrib import admin
from django.urls import path
from django.contrib.auth import views as auth_views
from dashboard import views

urlpatterns = [
    # this is the authentication sectio to log in into project
    path('admin/', admin.site.urls),
    path('', views.index, name='index'),
    path('register/', views.register, name='register'),
    path('login/', auth_views.LoginView.as_view(template_name='dashboard/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='/login/'), name='logout'),
    
    # feature embedded in this project such as uploading, capturing data, aleting and exporting report
    path('upload-pcap/', views.handle_pcap_upload, name='upload_pcap'),
    path('start-capture/', views.start_capture, name='start_capture'),
    path('resolve-alert/<int:alert_id>/', views.resolve_alert, name='resolve_alert'),
    path('export-excel/', views.export_excel_report, name='export_excel'),
    
    # here use of ai and ml such llama and alonwg with various evaluations
    path('ai-assistant/', views.ai_assistant, name='ai_assistant'), #for ai assitant
    path('llm-query/', views.llm_query, name='llm_query'),      #receivng messages from frontedn and sent it to LLM 
    path('generate-insight/', views.generate_insight, name='generate_insight'), #generates ai based insights like logs, attacks
    path('ml-models/', views.ml_models, name='ml_models'),         
    path('evaluation/', views.evaluation, name='evaluation'),
    path('threat-intel/', views.threat_intel, name='threat_intel'),   #displaying malware information, CVEs 
    path('api/model-metrics/', views.api_model_metrics, name='api_model_metrics'), #returns json file instead of an html page
    path('api/all-attacks/', views.api_all_attacks, name='api_all_attacks'), #it returns the all attack from the database
   
    
    # Investigation paths used
    path('live-traffic/', views.live_traffic, name='live_traffic'),    #used for live traffic monitoring
    path('alerts/', views.alerts_page, name='alerts_page'),           #displays the security alerts
    path('attack-timeline/', views.attack_timeline, name='attack_timeline'),   #shows attacks records from datbase with timestamp
    path('ip-explorer/', views.ip_explorer, name='ip_explorer'),        #this path allows user to invetigate on particular ip address
    path('packet-search/', views.packet_search, name='packet_search'),   #search for the captured networks
    path('stop-capture/', views.stop_capture, name='stop_capture'),        #stop the captured networks
    path('clear-alerts/', views.clear_alerts, name='clear_alerts'),      #delete all the records
      
    # API Endpoints
    path('dashboard-stats/', views.dashboard_stats, name='dashboard_stats'),  #it shows the summary statistics for the dashboard
    path('api/alerts/', views.api_alerts, name='api_alerts'),                # it gives current security alerts as JSON
    path('api/timeline/', views.api_timeline, name='api_timeline'),           #return the attack timeline in seuential order
    path('api/ip-details/<str:ip>/', views.api_ip_details, name='api_ip_details'),  # it shows the deatils of the ip address
    path('api/ip-details/search/', views.api_ip_search, name='api_ip_search'),    #searches for the ip address as per user inpurt on it
    
]