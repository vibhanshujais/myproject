import seaborn as sns
import sklearn
from sklearn import datasets
iris = datasets.load_iris()
sns.boxplot(data=iris_data, width=0.5, fliersize=5)
sns.set(rc={'figure.figsize':(2,5)})