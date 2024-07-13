from django.db import models

class MemoryDump(models.Model):
    file = models.FileField(upload_to='memory_dumps/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

class AnalysisResult(models.Model):
    memory_dump = models.ForeignKey(MemoryDump, on_delete=models.CASCADE)
    plugin_name = models.CharField(max_length=100)
    result = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, default='in_progress')
