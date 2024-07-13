from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import status
from django.shortcuts import get_object_or_404
from .models import MemoryDump, AnalysisResult
from .serializers import MemoryDumpSerializer, AnalysisResultSerializer
import os
import subprocess

class MemoryDumpUploadView(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, *args, **kwargs):
        file_serializer = MemoryDumpSerializer(data=request.data)
        if file_serializer.is_valid():
            file_serializer.save()
            return Response({"status": "success", "fileId": file_serializer.data['id']}, status=status.HTTP_201_CREATED)
        return Response(file_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class MemoryAnalysisView(APIView):
    def post(self, request, *args, **kwargs):
        data = request.data
        memory_dump = get_object_or_404(MemoryDump, id=data['fileId'])
        plugin_name = data['plugin']

        # Path to the memory dump file
        memory_dump_path = memory_dump.file.path

        # Import the plugin and run it
        if plugin_name == 'process_list':
            from plugins.process_list import ProcessList
            import volatility.conf as conf
            import volatility.registry as registry

            # Set up Volatility configuration
            config = conf.ConfObject()
            registry.PluginImporter()
            config.parse_options()
            config.PROFILE = 'Win7SP1x64'
            config.LOCATION = f"file://{memory_dump_path}"

            # Run the plugin
            plugin = ProcessList(config)
            output = plugin.calculate()

            result_text = ""
            for process in output:
                result_text += f"{process.ImageFileName} - PID: {process.UniqueProcessId}, PPID: {process.InheritedFromUniqueProcessId}\n"

            analysis_result = AnalysisResult.objects.create(
                memory_dump=memory_dump,
                plugin_name=plugin_name,
                result=result_text,
                status='completed'
            )
            return Response({"status": "analysis_started", "analysisId": analysis_result.id}, status=status.HTTP_201_CREATED)
        return Response({"status": "failed", "error": "Invalid plugin name"}, status=status.HTTP_400_BAD_REQUEST)

class AnalysisStatusView(APIView):
    def get(self, request, analysisId, *args, **kwargs):
        analysis_result = get_object_or_404(AnalysisResult, id=analysisId)
        return Response({"status": analysis_result.status}, status=status.HTTP_200_OK)

class AnalysisResultsView(APIView):
    def get(self, request, analysisId, *args, **kwargs):
        analysis_result = get_object_or_404(AnalysisResult, id=analysisId)
        return Response({"status": "success", "results": analysis_result.result}, status=status.HTTP_200_OK)

class AnalysisResultListView(APIView):
    def get(self, request, *args, **kwargs):
        analysis_results = AnalysisResult.objects.all()
        serializer = AnalysisResultSerializer(analysis_results, many=True)
        return Response({"analyses": serializer.data}, status=status.HTTP_200_OK)



def main_page(request, error_line=None):
    """
    Returns the main vol page
    :param request:
    :param error_line:
    :return:
    """

    # Check Vol Version
    try:
        vol_ver = vol_interface.vol_version.split('.')
        if int(vol_ver[1]) < 5:
            error_line = 'UNSUPPORTED VOLATILITY VERSION. REQUIRES 2.5 FOUND {0}'.format(vol_interface.vol_version)
    except Exception as error:
        error_line = 'Unable to find a volatility version'
        logger.error(error_line)


    if 'auth' in config:
        if config['auth']['enable'].lower() == 'true' and not request.user.is_authenticated:
            return render(request, 'index.html', {'reqauth': True,
                                                  'error_line': error_line
                                                  })


    # Set Pagination
    page = request.GET.get('page')
    if not page:
        page = 1
    page_count = request.GET.get('count')
    if not page_count:
        page_count = 30
    # Get All Sessions
    session_list = db.get_allsessions()
    # Paginate
    session_count = len(session_list)
    first_session = int(page) * int(page_count) - int(page_count) + 1
    last_session = int(page) * int(page_count)
    paginator = Paginator(session_list, page_count)
    try:
        sessions = paginator.page(page)
    except PageNotAnInteger:
        sessions = paginator.page(1)
    except EmptyPage:
        sessions = paginator.page(paginator.num_pages)
    # Show any extra loaded plugins
    plugin_dirs = []
    if os.path.exists(volrc_file):
        vol_conf = open(volrc_file, 'r').readlines()
        for line in vol_conf:
            if line.startswith('PLUGINS'):
                plugin_dirs = line.split(' = ')[-1]

    # Profile_list for add session
    RunVol('', '')
    profile_list = vol_interface.profile_list()

    return render(request, 'index.html', {'session_list': sessions,
                                          'session_counts': [session_count, first_session, last_session],
                                          'profile_list': profile_list,
                                          'plugin_dirs': plugin_dirs,
                                          'error_line': error_line,
                                          'reqauth': False
                                          })