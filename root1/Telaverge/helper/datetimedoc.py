import tempfile
import logging
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
#import regal.logger.logger as logger
from regal.docgen import DocGenerator, image_wrapper
#from regal.utility import Utility
#from regal.constants import Constants
from regal_lib.corelib.common_utility import Utility
from regal_lib.corelib.constants import Constants

matplotlib.use('Agg')


# plt.rcParams.update({'figure.max_open_warning': 0}) need to close the file

logging.basicConfig(level=logging.DEBUG)

class DatetimeDoc(object):
    def __init__(self,service_store_obj, datetime_tpl_file, data):
        """Intilisation of the class.

        Args:
            datetime_tpl_file(str): The full file path of the stp template docx file.
            data(dict): The dictionary containing all the data to be filled in
            the template docx.

        Returns:
            None

        """
        super(DatetimeDoc, self).__init__(service_store_obj,datetime_tpl_file, data)
        self._classname = self.__class__.__name__
        self.service_store_obj = service_store_obj
        self._log_mgr_obj = self.service_store_obj.get_log_mgr_obj()
        self._log = self._log_mgr_obj.get_logger(self.__class__.__name__)
        self.tpl_file = datetime_tpl_file
        self.data = data
        self.doc = DocGenerator(self.tpl_file)#==========

    def create(self, filename):
        """Create the final docx from the template given.

        Args:
            filename(str): The full file path for the doc to be saved.

        Returns:
            None

        """
        context = self._make_context(self.data)
        self.doc.create(context, filename)

    def _make_context(self, data):
        """Helper for making context from data

        Args:
            data(dict): data for the stp document generation

        Returns:
            dict

        """
        context = data
        context['benchmarks'] = self._mk_benchmark_ctx(data['benchmarks'])
        return context

    def _mk_benchmark_ctx(self, details):
        """Helper function for creating benchmark context data

        Args:
            details(dict): dictionary for the benchmark data

        Returns:
            dict

        """
        bench_mark_info = []
        info = {}
        info["header"] = details["header"]
        for item in details["data"]:
            item_info = {}
            item_info["result"] = item["result"]
            images = []
            for graph in item["graphs"]:
                if len(list(graph.keys())) < 5:
                    xlabel = graph.get('xlabel', 'x')
                    ylabel = graph.get('ylabel', 'y')
                    title = graph.get('title', 'Untitled')
                    data_points = graph.get('points')
                    x_vals, y_vals = list(zip(*data_points))
                    image_name = self.mk_graph_image(x_vals, y_vals, xlabel, ylabel, title)
                    images.append({'image': image_wrapper(self.doc, image_name)})
                    item_info['images'] = images
                else:
                    x_label = graph.get('x_label')
                    y1_label = graph.get('y1_label')
                    y2_label = graph.get('y2_label')
                    y3_label = graph.get('y3_label')
                    y4_label = graph.get('y4_label')
                    title = graph.get('title')
                    points_1 = graph.get('points_1')
                    points_2 = graph.get('points_2')
                    points_3 = graph.get('points_3')
                    points_4 = graph.get('points_4')
                    x1_val, y1_val = list(zip(*points_1))
                    x2_val, y2_val = list(zip(*points_2))
                    x3_val, y3_val = list(zip(*points_3))
                    x4_val, y4_val = list(zip(*points_4))
                    image_name = self.mk_merged_graph_image(
                        x1_val, y1_val, x2_val, y2_val, x3_val,
                        y3_val, x4_val, y4_val, x_label, y1_label, y2_label, y3_label, y4_label, title)
                    images.append({'image': image_wrapper(self.doc, image_name)})
                    item_info['images'] = images
            bench_mark_info.append(item_info)
        info["data"] = bench_mark_info
        self._log.debug("<")
        return [info]


    def mk_graph_image(self, x_vals, y_vals, xlabel, ylabel, title):
        """Helper function for making graph images

        Args:
            x_vals(list): data points for x axis
            y_vals(list): data points for y axis
            xlabel(str): label for x-axis
            ylabel(str): label for y-axis
            title(str): title for the image

        Returns:
            None

        """
        x_vals_ = Utility.get_datetime_object(x_vals)#======>
        image_name = tempfile.NamedTemporaryFile()
        image_name.close()
        image_name = '{}.png'.format(image_name.name)
        fig, ax1 = plt.subplots()

        ax1.xaxis.set_major_formatter(mdates.DateFormatter(Constants.GRAPH_TIMESTAMP_FORMAT))#====
        ax1.tick_params(axis='x', labelrotation=90, labelsize=10)
        ax1.ticklabel_format(axis='y', useOffset=False, style='plain')
        ax1.plot(x_vals_, y_vals)
        ax1.set_xlabel(xlabel, fontsize=10)
        ax1.set_ylabel(ylabel, fontsize=10)
        ax1.set_title(title)
        plt.tight_layout()
        logging.debug("labels x: %s y: %s", str(xlabel), str(ylabel))
        plt.savefig(image_name, format='png')
        plt.close(fig)
        return '{}'.format(image_name)

    def mk_merged_graph_image(self, x1_vals, y1_vals, x2_vals, y2_vals,
                              x3_vals, y3_vals, x4_vals, y4_vals, x_label, y1label, y2label, y3label, y4label, title):
        """ This method creates the merge the graph image.

        Args:
            x1_vals(str): x axis value for one graph
            y1_vals(str): y axis value for one graph
            x2_vals(str): x axis value for second graph
            y2_vals(str): y axis value for second graph
            xlabel(str): x axis label name
            y1label(str): y axis label name
            y2label(str): x axis label name of seconda graph
            title(str): title of the graph

        Returns:
            None

        """
        x1_vals = Utility.get_datetime_object(x1_vals)#=====
        x2_vals = Utility.get_datetime_object(x2_vals)
        x3_vals = Utility.get_datetime_object(x3_vals)
        x4_vals = Utility.get_datetime_object(x4_vals)
        image_name = tempfile.NamedTemporaryFile()
        image_name.close()
        image_name = '{}.png'.format(image_name.name)
        fig, ax1 = plt.subplots(1)
        ax1.set_xlabel(x_label, fontsize=10)
        ax1.set_title(title, fontsize=10)

        ax1.xaxis.set_major_formatter(mdates.DateFormatter(Constants.GRAPH_TIMESTAMP_FORMAT))
        ax1.tick_params(axis='x', labelrotation=90, labelsize=10)
        ax1.ticklabel_format(axis='y', useOffset=False, style='plain')
        ax1.xaxis_date()
        level1, level2 = ax1.plot(x1_vals, y1_vals, 'y', x2_vals, y2_vals, 'r')

        ax2 = ax1.twinx()

        ax2.xaxis.set_major_formatter(mdates.DateFormatter(Constants.GRAPH_TIMESTAMP_FORMAT))
        ax2.tick_params(axis='x', labelrotation=90, labelsize=10)
        ax2.ticklabel_format(axis='y', useOffset=False, style='plain')
        ax2.xaxis_date()
        level3, level4 = ax2.plot(x3_vals, y3_vals, 'g', x4_vals, y4_vals, 'b')

        fig.legend((level1, level2), (y1label, y2label), 'upper left',
                   fontsize=10, bbox_to_anchor=(0.0, 1.03))
        fig.legend((level3, level4), (y3label, y4label), 'upper right',
                   fontsize=10, bbox_to_anchor=(1.0, 1.03))

        plt.tight_layout()
        plt.savefig(image_name, format='png')
        plt.close(fig)
        return '{}'.format(image_name)

    def _get_unit_from_label(self, label):
        """Helper function to get unit of the label passed.

        Args:
            label(str): string which contain the unit

        Returns:
            str

        """
        return label.split("(")[1].split(")")[0]
