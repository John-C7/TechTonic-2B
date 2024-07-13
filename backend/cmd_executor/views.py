from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import status
from django.shortcuts import get_object_or_404
from .models import MemoryDump, AnalysisResult
from .serializers import MemoryDumpSerializer, AnalysisResultSerializer
import os
import subprocess

def start_memory_analysis(request):
    file_id = request.data.get('fileId')
    plugin = request.data.get('plugin')
    try:
        memory_dump = MemoryDump.objects.get(id=file_id)
        analysis = Analysis.objects.create(memory_dump=memory_dump, plugin=plugin, status='analysis_started')

        # Define the plugin path and memory dump file path
        plugin_path = os.path.join('../plugins', plugin)
        memory_dump_path = memory_dump.file.path

        # Check if the plugin exists
        if not os.path.isfile(plugin_path):
            analysis.status = 'failed'
            analysis.results = 'Plugin not found'
            analysis.save()
            return Response({"error": "Plugin not found"}, status=status.HTTP_404_NOT_FOUND)

        # Execute the plugin
        process = Popen([plugin_path, memory_dump_path], stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            analysis.status = 'completed'
            analysis.results = stdout.decode('utf-8')
        else:
            analysis.status = 'failed'
            analysis.results = stderr.decode('utf-8')

        analysis.save()
        return Response({"status": "analysis_started", "analysisId": analysis.id}, status=status.HTTP_201_CREATED)
    except MemoryDump.DoesNotExist:
        return Response({"error": "Memory dump not found"}, status=status.HTTP_404_NOT_FOUND)
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


def session_creation(request, mem_image, session_id):
    if 'auth' in config:
        if config['auth']['enable'].lower() == 'true' and not request.user.is_authenticated:
            return HttpResponse('Auth Required.')

    # Get some vars
    new_session = db.get_session(session_id)
    file_hash = False
    if 'description' in request.POST:
        new_session['session_description'] = request.POST['description']
    if 'plugin_path' in request.POST:
        new_session['plugin_path'] = request.POST['plugin_path']
    if 'file_hash' in request.POST:
        file_hash = True
    # Check for mem file
    if not os.path.exists(mem_image):
        logger.error('Unable to find an image file at {0}'.format(mem_image))
        new_session['status'] = 'Unable to find an image file at {0}'.format(request.POST['sess_path'])
        return
    new_session['session_path'] = mem_image
    # Generate FileHash (MD5 for now)
    if file_hash:
        logger.debug('Generating MD5 for Image')
        # Update the status
        new_session['status'] = 'Calculating MD5'
        db.update_session(session_id, new_session)
        md5_hash = checksum_md5(new_session['session_path'])
        new_session['file_hash'] = md5_hash

    # Get a list of plugins we can use. and prepopulate the list.
    if 'profile' in request.POST:
        if request.POST['profile'] != 'AutoDetect':
            profile = request.POST['profile']
            new_session['session_profile'] = profile
        else:
            profile = None
    else:
        profile = None

    vol_int = RunVol(profile, new_session['session_path'])
    image_info = {}
    if not profile:
        logger.debug('AutoDetecting Profile')
        # kdbg scan to get a profile suggestion
        # Update the status
        new_session['status'] = 'Detecting Profile'
        db.update_session(session_id, new_session)
        # Doesnt support json at the moment
        kdbg_results = vol_int.run_plugin('kdbgscan', output_style='text')
        lines = kdbg_results['rows'][0][0]
        profiles = []
        for line in lines.split('\n'):
            if 'Profile suggestion' in line:
                profiles.append(line.split(':')[1].strip())
        if len(profiles) == 0:
            logger.error('Unable to find a valid profile with kdbg scan')
            return main_page(request, error_line='Unable to find a valid profile with kdbg scan')
        profile = profiles[0]
        # Re initialize with correct profile
        vol_int = RunVol(profile, new_session['session_path'])
    # Get compatible plugins
    plugin_list = vol_int.list_plugins()
    new_session['session_profile'] = profile
    new_session['image_info'] = image_info
    # Plugin Options
    plugin_filters = vol_interface.plugin_filters
    # Update Session
    new_session['status'] = 'Complete'
    db.update_session(session_id, new_session)
    # Autorun list from config
    if config['autorun']['enable'] == 'True':
        auto_list = config['autorun']['plugins'].split(',')
    else:
        auto_list = False
    # Merge Autorun from manual post with config
    if 'auto_run' in request.POST:
        run_list = request.POST['auto_run'].split(',')
        if not auto_list:
            auto_list = run_list
        else:
            for run in run_list:
                if run not in auto_list:
                    auto_list.append(run)
    # For each plugin create the entry
    for plugin in plugin_list:
        plugin_name = plugin[0]
        db_results = {'session_id': session_id, 'plugin_name': plugin_name}
        # Ignore plugins we cant handle
        if plugin_name in plugin_filters['drop']:
            continue
        plugin_output = plugin_status = None
        # Create placeholders for dumpfiles and memdump
        if plugin_name == 'dumpfiles':
            plugin_output = {'columns': ['Offset', 'File Name', 'Image Type', 'StoredFile'], 'rows': []}
            plugin_status = 'complete'
        elif plugin_name == 'memdump':
            plugin_output = {'columns': ['Process', 'PID', 'StoredFile'], 'rows': []}
            plugin_status = 'complete'
        db_results['help_string'] = plugin[1]
        db_results['created'] = None
        db_results['plugin_output'] = plugin_output
        db_results['status'] = plugin_status
        # Write to DB
        plugin_id = db.create_plugin(db_results)

        if auto_list:
            if plugin_name in auto_list:
                multiprocessing.Process(target=run_plugin, args=(session_id, plugin_id)).start()



