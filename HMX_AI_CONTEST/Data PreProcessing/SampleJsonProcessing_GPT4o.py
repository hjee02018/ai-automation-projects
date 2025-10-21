import json
import os


# Utility function to convert bounding box coordinates into YOLO format
def convert_bbox_to_yolo_format(bbox, img_width, img_height):
    x_min, y_min, bbox_width, bbox_height = bbox
    x_center = (x_min + bbox_width / 2) / img_width
    y_center = (y_min + bbox_height / 2) / img_height
    norm_width = bbox_width / img_width
    norm_height = bbox_height / img_height
    return x_center, y_center, norm_width, norm_height


# Utility function to convert polygon coordinates into normalized YOLO format
def convert_polygon_to_yolo_format(polygon, img_width, img_height):
    normalized_polygon = []
    for point in polygon:
        x, y = point
        normalized_x = x / img_width
        normalized_y = y / img_height
        normalized_polygon.append(f"{normalized_x} {normalized_y}")
    return " ".join(normalized_polygon)


def convert_json_to_yolo(json_file, output_dir_bbox, output_dir_segmentation):
    # Create output directories if they don't exist
    os.makedirs(output_dir_bbox, exist_ok=True)
    os.makedirs(output_dir_segmentation, exist_ok=True)

    # Load the JSON data
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Extract image resolution
    img_width, img_height = data["Raw data Info."]["resolution"]

    # Get the list of annotations
    annotations = data["Learning data info."]["annotation"]

    # Get JSON file base name for output filenames
    json_basename = os.path.splitext(os.path.basename(json_file))[0]

    # File to store bounding boxes
    bbox_output_file = os.path.join(output_dir_bbox, f"{json_basename}.txt")
    # File to store segmentation (polygon) data
    seg_output_file = os.path.join(output_dir_segmentation, f"{json_basename}.txt")

    with open(bbox_output_file, 'w') as bbox_file, open(seg_output_file, 'w') as seg_file:
        for ann in annotations:
            class_id = ann['class_id']

            # If the annotation is a bounding box
            if ann['type'] == 'box':
                bbox = ann['coord']
                x_center, y_center, width, height = convert_bbox_to_yolo_format(bbox, img_width, img_height)
                bbox_file.write(f"{class_id} {x_center} {y_center} {width} {height}\n")

            # If the annotation is a polygon (segmentation)
            elif ann['type'] == 'polygon':
                polygon = ann['coord']
                normalized_polygon = convert_polygon_to_yolo_format(polygon, img_width, img_height)
                seg_file.write(f"{class_id} {normalized_polygon}\n")


# Example usage
json_file = 'SampleFile/L-210916_G03_D_WS-09_001_0001.JSON'  # Replace with your actual file path
output_dir_bbox = './bounding_box_annotations'
output_dir_segmentation = './segmentation_annotations'

convert_json_to_yolo(json_file, output_dir_bbox, output_dir_segmentation)
