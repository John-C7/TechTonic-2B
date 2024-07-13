from rest_framework import serializers
from .models import MemoryDump, AnalysisResult

class MemoryDumpSerializer(serializers.ModelSerializer):
    class Meta:
        model = MemoryDump
        fields = '__all__'

class AnalysisResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnalysisResult
        fields = '__all__'
