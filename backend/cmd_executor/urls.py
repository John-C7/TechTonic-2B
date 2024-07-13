from django.urls import path
from .views import (
    MemoryDumpUploadView,
    MemoryAnalysisView,
    AnalysisStatusView,
    AnalysisResultsView,
    AnalysisResultListView
)

urlpatterns = [
    path('memory-dump/', MemoryDumpUploadView.as_view(), name='memory-dump-upload'),
    path('analyze/', MemoryAnalysisView.as_view(), name='memory-analysis'),
    path('analysis/<int:analysisId>/status/', AnalysisStatusView.as_view(), name='analysis-status'),
    path('analysis/<int:analysisId>/results/', AnalysisResultsView.as_view(), name='analysis-results'),
    path('analyses/', AnalysisResultListView.as_view(), name='analysis-list'),
]
